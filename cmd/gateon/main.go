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

	"github.com/gsoultan/gateon/cmd/gateon/inits"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/ha"
	"github.com/gsoultan/gateon/internal/install"
	"github.com/gsoultan/gateon/internal/k8s"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/server"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/tui"
	"github.com/gsoultan/gateon/internal/ui"
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

	_ = logger.Init(logger.IsProd())
	defer logger.Sync()

	globalReg, globalFile := initConfigRegistries()
	authManager := inits.InitGlobalConfig(globalFile, globalReg)
	if authManager != nil {
		defer authManager.Close()
	}

	shutdown, err := telemetry.InitTracer("server")
	if err == nil {
		defer func() {
			if err := shutdown(context.Background()); err != nil {
				logger.L.Error().Err(err).Msg("failed to shutdown tracer")
			}
		}()
	}

	initTelemetry(globalReg)

	if gc := globalReg.Get(context.Background()); gc != nil {
		if gc.Ha != nil && gc.Ha.Enabled {
			haManager := ha.NewHAManager(gc.Ha)
			go haManager.Start(context.Background()) // It will stop when ctx is cancelled in Run
		}
		if gc.AnomalyDetection != nil && gc.AnomalyDetection.Enabled {
			ad, err := telemetry.NewAnomalyDetector(gc.AnomalyDetection)
			if err != nil {
				logger.L.Error().Err(err).Msg("failed to init anomaly detector")
			} else {
				go ad.Start(context.Background())
			}
		}
		if gc.Ebpf != nil && gc.Ebpf.Enabled {
			ebpfManager := ebpf.NewEbpfManager(gc.Ebpf)
			go ebpfManager.Start(context.Background())
		}
	}

	port := getPort()
	s, err := server.NewServer(
		server.WithGlobalRegistry(globalReg),
		server.WithAuthManager(authManager),
		server.WithPort(port),
		server.WithVersion(version()),
		server.WithRouteRegistry(config.NewRouteRegistry(getEnvDefault("ROUTES_FILE", "routes.json"))),
		server.WithServiceRegistry(config.NewServiceRegistry(getEnvDefault("SERVICES_FILE", "services.json"))),
		server.WithEntryPointRegistry(config.NewEntryPointRegistry(getEnvDefault("ENTRYPOINTS_FILE", "entrypoints.json"))),
		server.WithMiddlewareRegistry(config.NewMiddlewareRegistry(getEnvDefault("MIDDLEWARES_FILE", "middlewares.json"))),
		server.WithTLSOptionRegistry(config.NewTLSOptionRegistry(getEnvDefault("TLS_OPTIONS_FILE", "tls_options.json"))),
	)
	if err != nil {
		logger.L.Fatal().Err(err).Msg("failed to create server")
	}
	if redisAddr := os.Getenv("REDIS_ADDR"); redisAddr != "" {
		s.RedisClient = redis.NewClient(redisAddr)
		logger.L.Info().Str("addr", redisAddr).Msg("redis client initialized")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		startK8sController(ctx, s)
	}

	uiHandler := getUIHandler(*uiPath)
	server.Run(ctx, s, uiHandler)
}

func buildUIAssets(uiPath *string) {
	logger.L.Info().Msg("building UI assets...")
	cmd := exec.Command("go", "generate", "./internal/ui")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		logger.L.Error().Err(err).Msg("error building UI")
		os.Exit(1)
	}
	logger.L.Info().Msg("UI build complete.")
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

func initTelemetry(globalReg *config.GlobalRegistry) {
	if !globalReg.ConfigFileExists() {
		return
	}
	if gc := globalReg.Get(context.Background()); gc != nil {
		databaseURL := db.AuthDatabaseURL(gc.Auth)
		retention := 7
		if gc.Log != nil && gc.Log.PathStatsRetentionDays > 0 {
			retention = int(gc.Log.PathStatsRetentionDays)
		}
		if err := telemetry.InitPathStatsStore(databaseURL, retention); err != nil {
			logger.L.Error().Err(err).Str("database_url", databaseURL).Msg("failed to init path stats store")
		}
	}
}

func startK8sController(ctx context.Context, s *server.Server) {
	config, err := rest.InClusterConfig()
	if err != nil {
		logger.L.Error().Err(err).Msg("failed to get k8s in-cluster config")
		return
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.L.Error().Err(err).Msg("failed to create k8s clientset")
		return
	}
	gwClient, err := gatewayclient.NewForConfig(config)
	if err != nil {
		logger.L.Error().Err(err).Msg("failed to create gateway clientset")
		return
	}
	ctrl := k8s.NewController(clientset, gwClient, s.RouteStore, s.ServiceStore)
	go ctrl.Run(ctx.Done())
	logger.L.Info().Msg("Kubernetes Controller (Ingress + Gateway API) started")
}

func getPort() string {
	if port := os.Getenv("PORT"); port != "" {
		return port
	}
	return "8080"
}

func getUIHandler(uiPath string) http.Handler {
	if uiPath != "" {
		logger.L.Info().Str("path", uiPath).Msg("serving UI assets from disk")
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
