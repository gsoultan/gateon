// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gsoultan/gateon/internal/ai"
	"github.com/gsoultan/gateon/internal/alerting"
	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/inits"
	"github.com/gsoultan/gateon/internal/install"
	"github.com/gsoultan/gateon/internal/k8s"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/phantom"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/repositories/stores"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/resource"
	"github.com/gsoultan/gateon/internal/security"
	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/server"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/tui"
	"github.com/gsoultan/gateon/internal/ui"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

func main() {
	uiPath := flag.String("ui-path", "", "Path to UI assets (serves from disk instead of embed)")
	aiModel := flag.String("ai-model", "", "Path to WASM-based AI traffic prediction model")
	buildUI := flag.Bool("build-ui", false, "Build UI assets before starting")
	builtUI := flag.Bool("built-ui", false, "Alias for build-ui")
	flag.Parse()

	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "install":
			if err := install.Install(); err != nil {
				fmt.Fprintf(os.Stderr, "install: %v\n", err)
				os.Exit(1)
			}
			return
		case "uninstall":
			if err := install.Uninstall(); err != nil {
				fmt.Fprintf(os.Stderr, "uninstall: %v\n", err)
				os.Exit(1)
			}
			return
		case "top":
			apiURL := "http://localhost:" + getPort()
			if len(os.Args) >= 3 {
				apiURL = os.Args[2]
			}
			if err := tui.RunTop(context.Background(), apiURL); err != nil {
				fmt.Fprintf(os.Stderr, "top: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	if *buildUI || *builtUI {
		buildUIAssets(uiPath)
	}

	if err := logger.Init(logger.IsProd()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Apply container-aware runtime tuning (GOMAXPROCS awareness, optional soft
	// memory limit and GC target) before any allocation-heavy subsystem starts.
	tuneRuntime()

	globalReg, globalFile := initConfigRegistries()
	auth.SetConfigGetter(globalReg)
	authManager := inits.InitGlobalConfig(globalFile, globalReg)
	if authManager != nil {
		defer authManager.Close()
	}

	shutdown, err := telemetry.InitTracer("server")
	if err == nil {
		defer func() {
			if err := shutdown(context.Background()); err != nil {
				logger.L.LogError("failed to shutdown tracer", "error", err)
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Opt-in runtime profiling (off unless GATEON_PPROF_ADDR is set).
	startPprofServer(ctx)

	initTelemetry(globalReg, ctx)

	// Configure logger with global config if present
	if g := globalReg.Get(ctx); g != nil && g.Log != nil {
		_ = logger.InitWithConfig(g.Log.Level, logger.IsProd())
	}

	// Initialize WAF rules store
	if gc := globalReg.Get(ctx); gc != nil {
		databaseURL := db.AuthDatabaseURL(gc.Auth)
		if err := waf.InitStore(databaseURL); err != nil {
			logger.L.LogError("failed to init waf rules store", "error", err)
		} else {
			waf.GetStore().SetInvalidator(middleware.WAFCacheInvalidator{})
		}
	}

	// The eBPF subsystem is driven through a Holder: an atomic indirection that
	// every consumer (alerting, the request-path server, the metrics poll loop)
	// references, so the security supervisor can hot-swap the underlying eBPF
	// manager when Ebpf.Enabled toggles — without invalidating any captured
	// pointer or forcing a restart. The supervisor's first reconcile applies the
	// boot-time config (privilege gating, Start, poll loop).
	ebpfHolder := ebpf.GlobalHolder
	telemetry.SetEbpfManager(&ebpfAdapter{ebpfHolder})
	var wafUpdater *middleware.WAFUpdater
	var clamavManager *security.ClamAVManager

	if gc := globalReg.Get(ctx); gc != nil {
		alerting.Init(gc.Alerting, ebpfHolder)
		telemetry.SetAlertingHandler(alerting.HandleThreat)
		databaseURL := db.AuditDatabaseURL(gc.Audit, gc.Auth)
		if err := audit.Init(gc.Audit, databaseURL); err != nil {
			logger.L.LogError("failed to init audit manager", "error", err)
		}

		if gc.Ha != nil && gc.Ha.Enabled {
			// Gossip reputation sync exposes no stop hook, so it stays boot-only.
			if err := telemetry.InitGossip(gc.Ha); err != nil {
				logger.L.LogError("failed to init gossip reputation sync", "error", err)
			}
		}
		wafUpdater = middleware.NewWAFUpdater(globalReg, ".")
		// The WAF auto-update loop and ClamAV manager lifecycles are managed by the
		// security supervisor below so toggling Waf.AutoUpdateRules / Waf.Clamav
		// takes effect without a restart. The ClamAV manager is always created
		// (even when initially disabled) so it can be reconfigured at runtime; the
		// supervisor's first reconcile applies the boot-time config (cron + auto-install).
		clamavManager = security.NewClamAVManager(gc.GetWaf().GetClamav())
	}

	// Manage hot-reloadable background security subsystems (anomaly detection,
	// GitOps, HA, WAF rule auto-update). Toggling these in the config now takes
	// effect without a restart. Pass a properly-nil interface when the updater
	// was not created, so the supervisor's nil check works as intended.
	var wafAuto wafAutoUpdater
	if wafUpdater != nil {
		wafAuto = wafUpdater
	}
	var clamavReconf clamavReconfigurer
	if clamavManager != nil {
		clamavReconf = clamavManager
	}
	newSecuritySupervisor(ctx, globalReg, ebpfHolder, wafAuto, clamavReconf).Run()

	// Correlate recorded threats into MITRE-annotated incidents, drive graduated
	// mitigation (reputation degrade -> restrict -> optional eBPF shun), and (when
	// configured via GATEON_SIEM_*) export them to an external SIEM.
	startThreatPipeline(ctx, version(), ebpfHolder)

	// Initialize the reputation store if enabled.
	var ipReputation *reputation.IPReputationStore
	if gc := globalReg.Get(ctx); gc != nil && gc.SecurityAdvanced != nil && gc.SecurityAdvanced.IpReputation != nil {
		ipReputation = reputation.NewIPReputationStore(gc.SecurityAdvanced.IpReputation)
		ipReputation.Start(ctx)
	}

	// Initialize TITAN Phantom core for hardware acceleration.
	phantomCore := phantom.NewPhantomCore(ebpfHolder)

	// Load AI model if provided, or use default.
	var wasmBytes []byte
	if *aiModel != "" {
		var err error
		wasmBytes, err = os.ReadFile(*aiModel)
		if err != nil {
			logger.L.LogError("failed to read AI model file", "path", *aiModel, "error", err)
		} else {
			logger.L.LogInfo("AI traffic predictor initialized from external WASM", "path", *aiModel)
		}
	}

	if len(wasmBytes) == 0 {
		wasmBytes = ai.DefaultModelWasm
		logger.L.LogInfo("AI traffic predictor initialized from built-in default model")
	}

	if len(wasmBytes) > 0 {
		if err := ai.InitGlobalPredictor(ctx, wasmBytes); err != nil {
			logger.L.LogError("failed to initialize AI predictor", "error", err)
		}
	}

	// Initialize Resource Governor for real-time pressure monitoring and protection.
	gov := resource.NewGovernor()
	go gov.Start(ctx)

	port := getPort()

	// Initialize configuration registries. Default to database-backed if a management
	// database is configured; otherwise fall back to file-based registries.
	var routeStore config.RouteStore
	var serviceStore config.ServiceStore
	var epStore config.EntryPointStore
	var mwStore config.MiddlewareStore
	var tlsOptStore config.TLSOptionStore

	if authManager != nil && authManager.DB() != nil {
		dbConn := authManager.DB()
		dialect := authManager.Dialect()
		routeStore = stores.NewDBRouteRegistry(dbConn, dialect)
		serviceStore = stores.NewDBServiceRegistry(dbConn, dialect)
		epStore = stores.NewDBEntryPointRegistry(dbConn, dialect)
		mwStore = stores.NewDBMiddlewareRegistry(dbConn, dialect)
		tlsOptStore = stores.NewDBTLSOptionRegistry(dbConn, dialect)
		logger.L.LogInfo("using database-backed configuration storage")

		// A database-backed store starts out empty, which would silently discard
		// the configuration files supplied by the operator. Import them once.
		seedConfigFromFiles(ctx, dbConfigStores{
			routes:      routeStore,
			services:    serviceStore,
			entryPoints: epStore,
			middlewares: mwStore,
			tlsOptions:  tlsOptStore,
		})
	} else {
		routeStore = config.NewRouteRegistry(getEnvDefault(routesFileEnv, routesFileDefault))
		serviceStore = config.NewServiceRegistry(getEnvDefault(servicesFileEnv, servicesFileDefault))
		epStore = config.NewEntryPointRegistry(getEnvDefault(entryPointsFileEnv, entryPointsFileDefault))
		mwStore = config.NewMiddlewareRegistry(getEnvDefault(middlewaresFileEnv, middlewaresFileDefault))
		tlsOptStore = config.NewTLSOptionRegistry(getEnvDefault(tlsOptionsFileEnv, tlsOptionsFileDefault))
		logger.L.LogInfo("using file-based configuration storage")
	}

	s, err := server.NewServer(
		server.WithLogger(logger.Default()),
		server.WithGlobalRegistry(globalReg),
		server.WithIPReputation(ipReputation),
		server.WithAuthManager(authManager),
		server.WithEbpfManager(ebpfHolder),
		server.WithWafUpdater(wafUpdater),
		server.WithClamAVManager(clamavManager),
		server.WithPhantomCore(phantomCore),
		server.WithGovernor(gov),
		server.WithPort(port),
		server.WithVersion(version()),
		server.WithRouteRegistry(routeStore),
		server.WithServiceRegistry(serviceStore),
		server.WithEntryPointRegistry(epStore),
		server.WithMiddlewareRegistry(mwStore),
		server.WithTLSOptionRegistry(tlsOptStore),
		server.WithWafRules(waf.GetStore()),
	)
	if err != nil {
		logger.Fatal("failed to create server", "error", err)
	}
	var redisCfg *gateonv1.RedisConfig
	if gc := globalReg.Get(ctx); gc != nil {
		redisCfg = gc.Redis
	}
	if opts, ok := redis.ResolveOptions(redisCfg, os.Getenv); ok {
		if opts.ClusterIgnoresDB() {
			logger.L.LogWarn("redis.db ignored: Redis Cluster has no SELECT, so every key lives in db 0",
				"configured_db", opts.DB)
		}
		s.RedisClient = redis.NewClient(opts)
		// The password is reported as set or not, never echoed.
		logger.L.LogInfo("redis client initialized",
			"addrs", opts.Addrs, "db", opts.DB, "password_set", opts.Password != "")
	}

	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		startK8sController(ctx, s)
	}

	uiHandler := getUIHandler(*uiPath)
	server.Run(ctx, s, uiHandler)
}

func buildUIAssets(uiPath *string) {
	logger.L.LogInfo("building UI assets...")
	cmd := exec.Command("go", "generate", "./internal/ui")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		logger.L.LogError("error building UI", "error", err)
		os.Exit(1)
	}
	logger.L.LogInfo("UI build complete.")
	if *uiPath == "" {
		*uiPath = "internal/ui/dist"
	}
}

func initConfigRegistries() (*config.GlobalRegistry, string) {
	globalFile := getEnvDefault("GLOBAL_CONFIG_FILE", "global.json")

	// A missing global.json is not an error — first run reaches the setup
	// wizard through it — but it must be visible. The zero-value config has the
	// WAF switched off, so an operator who mistyped a path or forgot a mount
	// otherwise gets an unprotected gateway that looks healthy.
	if _, err := os.Stat(globalFile); err != nil {
		logger.L.LogWarn("global config not found; starting on built-in defaults "+
			"(WAF disabled) — set GATEON_CONFIG_DIR or GLOBAL_CONFIG_FILE if this is unintended",
			"path", globalFile, "config_dir", config.ConfigDir())
	}
	return config.NewGlobalRegistry(globalFile), globalFile
}

func initTelemetry(globalReg *config.GlobalRegistry, ctx context.Context) {
	// Initialize global GeoIP for background resolution
	dbPath := ""
	asnDBPath := ""
	countryDBPath := ""
	if gc := globalReg.Get(ctx); gc != nil && gc.Geoip != nil {
		dbPath = gc.Geoip.DbPath
		asnDBPath = gc.Geoip.AsnDbPath
		countryDBPath = gc.Geoip.CountryDbPath
	}

	if err := telemetry.InitGeoIP(dbPath); err == nil {
		request.RegisterCountryResolver(&telemetry.GeoIPResolver{})
	} else {
		logger.L.LogWarn("failed to initialize GeoIP background resolver", "error", err)
	}

	// Initialize the optional ASN database so Top Attack Sources can display the
	// autonomous system of attacking IPs. A missing database is not fatal.
	if err := telemetry.InitGeoIPASN(asnDBPath); err != nil {
		logger.L.LogWarn("failed to initialize GeoIP ASN resolver", "error", err)
	}

	// Initialize the optional Country database used as a geolocation fallback.
	if err := telemetry.InitGeoIPCountry(countryDBPath); err != nil {
		logger.L.LogWarn("failed to initialize GeoIP Country resolver", "error", err)
	}

	// Start GeoIP worker
	go telemetry.StartGeoIPWorker(ctx, func() *gateonv1.GlobalConfig {
		return globalReg.Get(ctx)
	})

	// Initialize the persistent telemetry store regardless of whether a global
	// config file exists yet. Without it the store stays nil, GetSystemTrafficHistory
	// returns nothing, and the dashboard's "Traffic/Bandwidth over time" charts fall
	// back to volatile in-session deltas that only span from page load — so they
	// appear to "only show the last hour". When no config is present we resolve the
	// default database (gateon.db, matching AuthDatabaseURL's default) and retention.
	var gc *gateonv1.GlobalConfig
	if globalReg.ConfigFileExists() {
		gc = globalReg.Get(ctx)
	}
	databaseURL := db.AuthDatabaseURL(gc.GetAuth())
	// Default retention follows the active resource profile (minimal=1, standard=7,
	// enterprise=30); explicit config still overrides.
	retention := config.CurrentTierDefaults().RetentionDays
	if gc != nil && gc.Log != nil {
		if gc.Log.AccessLogRetentionDays > 0 {
			retention = int(gc.Log.AccessLogRetentionDays)
		} else if gc.Log.PathStatsRetentionDays > 0 {
			retention = int(gc.Log.PathStatsRetentionDays)
		}
	}
	if err := telemetry.InitPathStatsStore(databaseURL, retention); err != nil {
		logger.L.LogError("failed to init path stats store", "error", err, "database_url", databaseURL)
	}

	// Start background metrics snapshotting
	go telemetry.StartSnapshotLoop(ctx)
}

func startK8sController(ctx context.Context, s *server.Server) {
	config, err := rest.InClusterConfig()
	if err != nil {
		logger.L.LogError("failed to get k8s in-cluster config", "error", err)
		return
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.L.LogError("failed to create k8s clientset", "error", err)
		return
	}
	gwClient, err := gatewayclient.NewForConfig(config)
	if err != nil {
		logger.L.LogError("failed to create gateway clientset", "error", err)
		return
	}
	ctrl := k8s.NewController(clientset, gwClient, s.RouteStore, s.ServiceStore)
	go ctrl.Run(ctx.Done())
	logger.L.LogInfo("Kubernetes Controller (Ingress + Gateway API) started")
}

func getPort() string {
	if port := os.Getenv("PORT"); port != "" {
		return port
	}
	return "8080"
}

func getUIHandler(uiPath string) http.Handler {
	if uiPath != "" {
		logger.L.LogInfo("serving UI assets from disk", "path", uiPath)
		return ui.StaticHandler(os.DirFS(uiPath), ".")
	}
	return ui.Handler()
}

// getEnvDefault resolves a config file path: an explicit env var wins,
// otherwise the default filename is taken relative to config.ConfigDir().
//
// Resolving through ConfigDir is what makes GATEON_CONFIG_DIR mean something.
// Before this, the per-file env vars were the only lever and each default was a
// bare filename resolved against the process working directory — so a packaged
// install with /etc/gateon/routes.json loaded nothing unless the operator also
// set ROUTES_FILE, and the failure was silent.
func getEnvDefault(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return filepath.Join(config.ConfigDir(), def)
}

// Version is set at build time via -ldflags "-X main.Version=<tag>".
var Version string

func version() string {
	if Version != "" {
		return Version
	}
	if v := os.Getenv("VERSION"); v != "" {
		return v
	}
	return "dev"
}

type ebpfAdapter struct {
	*ebpf.Holder
}

func (a *ebpfAdapter) GetTopIPs(limit int) ([]ebpf.IPStat, error) {
	return a.Holder.GetTopIPs(limit)
}

func (a *ebpfAdapter) ShunIP(ip string) error {
	return a.Holder.ShunIP(ip)
}

func (a *ebpfAdapter) UnshunIP(ip string) error {
	return a.Holder.UnshunIP(ip)
}

func (a *ebpfAdapter) SetAdaptiveRateLimit(ip string, interval time.Duration) error {
	return a.Holder.SetAdaptiveRateLimit(ip, interval)
}
