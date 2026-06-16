package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

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
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security"
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
	buildUI := flag.Bool("build-ui", false, "Build UI assets before starting")
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

	if *buildUI {
		buildUIAssets(uiPath)
	}

	if err := logger.Init(logger.IsProd()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

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

	// The eBPF subsystem is driven through a Holder: an atomic indirection that
	// every consumer (alerting, the request-path server, the metrics poll loop)
	// references, so the security supervisor can hot-swap the underlying eBPF
	// manager when Ebpf.Enabled toggles — without invalidating any captured
	// pointer or forcing a restart. The supervisor's first reconcile applies the
	// boot-time config (privilege gating, Start, poll loop).
	ebpfHolder := ebpf.NewHolder(nil)
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

	// Correlate recorded threats into MITRE-annotated incidents and (when
	// configured via GATEON_SIEM_*) export them to an external SIEM.
	startThreatPipeline(ctx, version())

	port := getPort()
	s, err := server.NewServer(
		server.WithLogger(logger.Default()),
		server.WithGlobalRegistry(globalReg),
		server.WithAuthManager(authManager),
		server.WithEbpfManager(ebpfHolder),
		server.WithWafUpdater(wafUpdater),
		server.WithClamAVManager(clamavManager),
		server.WithPort(port),
		server.WithVersion(version()),
		server.WithRouteRegistry(config.NewRouteRegistry(getEnvDefault("ROUTES_FILE", "routes.json"))),
		server.WithServiceRegistry(config.NewServiceRegistry(getEnvDefault("SERVICES_FILE", "services.json"))),
		server.WithEntryPointRegistry(config.NewEntryPointRegistry(getEnvDefault("ENTRYPOINTS_FILE", "entrypoints.json"))),
		server.WithMiddlewareRegistry(config.NewMiddlewareRegistry(getEnvDefault("MIDDLEWARES_FILE", "middlewares.json"))),
		server.WithTLSOptionRegistry(config.NewTLSOptionRegistry(getEnvDefault("TLS_OPTIONS_FILE", "tls_options.json"))),
	)
	if err != nil {
		logger.Fatal("failed to create server", "error", err)
	}
	if redisAddr := os.Getenv("REDIS_ADDR"); redisAddr != "" {
		s.RedisClient = redis.NewClient(redisAddr)
		logger.L.LogInfo("redis client initialized", "addr", redisAddr)
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
	globalFile := os.Getenv("GLOBAL_CONFIG_FILE")
	if globalFile == "" {
		globalFile = "global.json"
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

	if !globalReg.ConfigFileExists() {
		return
	}
	if gc := globalReg.Get(ctx); gc != nil {
		databaseURL := db.AuthDatabaseURL(gc.Auth)
		retention := 7
		if gc.Log != nil {
			if gc.Log.AccessLogRetentionDays > 0 {
				retention = int(gc.Log.AccessLogRetentionDays)
			} else if gc.Log.PathStatsRetentionDays > 0 {
				retention = int(gc.Log.PathStatsRetentionDays)
			}
		}
		if err := telemetry.InitPathStatsStore(databaseURL, retention); err != nil {
			logger.L.LogError("failed to init path stats store", "error", err, "database_url", databaseURL)
		}
	}
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

func getEnvDefault(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
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
