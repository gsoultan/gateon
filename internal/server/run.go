package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/canary"
	dentrypoint "github.com/gsoultan/gateon/internal/domain/entrypoint"
	dmw "github.com/gsoultan/gateon/internal/domain/middleware"
	"github.com/gsoultan/gateon/internal/domain/route"
	"github.com/gsoultan/gateon/internal/domain/service"
	dtls "github.com/gsoultan/gateon/internal/domain/tls"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/security"
	"github.com/gsoultan/gateon/internal/server/entrypoint"
	"github.com/gsoultan/gateon/internal/server/handlers"
	"github.com/gsoultan/gateon/internal/syncutil"
	"github.com/gsoultan/gateon/internal/telemetry"
	gtls "github.com/gsoultan/gateon/internal/tls"
	"github.com/gsoultan/gateon/pkg/l4"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
)

// ShutdownTimeout is the maximum time to wait for servers to shut down gracefully.
const ShutdownTimeout = 30 * time.Second

// Run starts the gateway: gRPC server, REST mux, base handler, entrypoints, and proxy sync loop.
// It blocks until ctx is cancelled, then shuts down all servers gracefully and returns.
func Run(ctx context.Context, s *Server, uiHandler http.Handler) {
	var wg syncutil.WaitGroup
	l4Resolver := l4.NewResolver(s.RouteStore, s.ServiceStore)
	proxyInvalidator := NewServerProxyInvalidator(s, l4Resolver, s.RouteStore)
	if s.RedisClient != nil {
		proxyInvalidator = NewDistributedProxyInvalidator(proxyInvalidator, s.RedisClient)
		wg.Go(func() {
			StartInvalidationListener(ctx, proxyInvalidator, s.RedisClient)
		})
	}
	s.TLSManager = CreateTLSManager(s)
	var wafUpdater *middleware.WAFUpdater
	if s.WafUpdater != nil {
		wafUpdater = s.WafUpdater.(*middleware.WAFUpdater)
	}
	var clamavManager *security.ClamAVManager
	if s.ClamAVManager != nil {
		clamavManager = s.ClamAVManager.(*security.ClamAVManager)
	}
	fimScanner := startFIM(ctx, &wg)

	apiService := api.NewApiService(api.ApiServiceConfig{
		Version:            s.Version,
		Routes:             s.RouteStore,
		Services:           s.ServiceStore,
		Globals:            s.GlobalStore,
		EntryPoints:        s.EpStore,
		Middlewares:        s.MwStore,
		TLSOptions:         s.TLSOptStore,
		Auth:               s.AuthManager,
		Invalidator:        proxyInvalidator,
		TLSManager:         s.TLSManager,
		RouteStatsProvider: s.GetRouteStats,
		EbpfManager:        s.EbpfManager,
		WafUpdater:         wafUpdater,
		ClamAVManager:      clamavManager,
	})
	routeService := route.NewService(s.RouteStore, proxyInvalidator, s.Logger)
	serviceService := service.NewService(s.ServiceStore, s.RouteStore, proxyInvalidator, s.Logger)
	epService := dentrypoint.NewService(s.EpStore, s.Logger)
	mwFactory := middleware.NewFactory(s.RedisClient, s.GlobalStore, s.EbpfManager, ".")
	mwService := dmw.NewService(s.MwStore, s.RouteStore, proxyInvalidator, mwFactory, middleware.WAFCacheInvalidator{}, s.Logger)
	tlsOptService := dtls.NewService(s.TLSOptStore, s.RouteStore, proxyInvalidator, s.Logger)
	canaryService := canary.NewService(serviceService, s.Logger)

	grpcServer := grpc.NewServer(grpc.MaxConcurrentStreams(10000))
	gateonv1.RegisterApiServiceServer(grpcServer, apiService)
	// Internal API only: gRPC-Web for the dashboard. Allow all origins; auth protects the API.
	// User routes use the grpcweb middleware with per-route allowed_origins config.
	internalAPI := grpcweb.WrapServer(grpcServer,
		grpcweb.WithOriginFunc(func(string) bool { return true }),
		grpcweb.WithCorsForRegisteredEndpointsOnly(false),
	)
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, apiService, &handlers.Deps{
		RouteService:       routeService,
		ServiceService:     serviceService,
		EpService:          epService,
		MwService:          mwService,
		TLSOptService:      tlsOptService,
		CanaryService:      canaryService,
		AuthManager:        s.AuthManager,
		Version:            s.Version,
		StartTime:          s.StartTime(),
		RouteStatsProvider: s.GetRouteStats,
		SecurityPosture:    newPostureProvider(s.Version, s.GlobalStore, clamavManager, wafUpdater, fimScanner),
		InvalidateAllProxies: func() {
			s.InvalidateRouteProxies(func(*gateonv1.Route) bool { return true })
		},
	})

	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, internalAPI, mux)
	})
	// Login rate limit: 5 attempts per minute per IP to mitigate brute force.
	loginLimiter := middleware.NewRateLimiter(rate.Every(time.Minute/5), 5)
	baseHandler := CreateBaseHandler(uiHandler, BaseHandlerDeps{
		ProxyHandler: proxyHandler,
		RouteStore:   s.RouteStore,
		GlobalReg:    s.GlobalStore,
		Auth:         s.AuthManager,
		LoginLimiter: loginLimiter,
	}, internalAPI, mux)
	var mgmtConfig *gateonv1.ManagementConfig
	if gc := s.GlobalStore.Get(ctx); gc != nil {
		mgmtConfig = gc.Management
	}
	mgmtCors := BuildManagementCORS(mgmtConfig)
	tlsConfig, err := s.TLSManager.GetTLSConfig()
	if err != nil {
		logger.Fatal("failed to initialize tls", "error", err)
	}
	// When global TLS is not explicitly enabled but at least one entrypoint
	// has TLS turned on, create a minimal TLS config so that SNI can
	// dynamically serve per-route certificates.
	if tlsConfig == nil && anyEntrypointTLS(s.EpStore) {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		}
		logger.L.LogInfo("created base TLS config for entrypoint-level TLS (global TLS not enabled)")
	}
	SetupSNI(tlsConfig, s.TLSManager, SNIDeps{
		RouteStore:  s.RouteStore,
		GlobalStore: s.GlobalStore,
		TLSOptStore: s.TLSOptStore,
	})

	shutdownReg := &entrypoint.ShutdownRegistry{}
	entrypoint.StartServers(s.EpStore, s.Port, baseHandler, internalAPI, tlsConfig, s.TLSManager, mgmtCors, &wg, shutdownReg, entrypoint.WrapL4Resolver(l4Resolver), mgmtConfig, s.GlobalStore)
	// Initialize metrics subsystem
	telemetry.InitStartTime()
	metricsStop := make(chan struct{})
	telemetry.StartSystemMetricsCollector(metricsStop)
	go telemetry.StartCacheMetricsLoop(ctx)

	// Start TLS certificate expiry monitoring
	certInfos := collectCertInfos(ctx, s, s.TLSManager)
	telemetry.StartTLSCertMonitor(certInfos, metricsStop)

	logger.L.LogInfo("Gateon API Gateway started", "port", s.Port)

	wg.Go(func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.SyncProxies()
			}
		}
	})

	<-ctx.Done()
	logger.L.LogInfo("shutting down gracefully")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()
	shutdownReg.ShutdownAll(shutdownCtx)
	grpcServer.GracefulStop()
	if s.RedisClient != nil {
		if closer, ok := s.RedisClient.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
	s.Close()
	close(metricsStop)
	wg.Wait()
	logger.L.LogInfo("shutdown complete")
}

// collectCertInfos gathers TLS certificate info from global TLS config and TLS Manager for expiry monitoring.
func collectCertInfos(ctx context.Context, s *Server, tlsManager gtls.TLSManager) []telemetry.CertInfo {
	var certs []telemetry.CertInfo
	seen := make(map[string]bool)

	// Collect from TLS Manager (handles both global config and environment variables)
	if tlsManager != nil {
		for _, c := range tlsManager.Certificates() {
			if c.CertFile == "" || c.KeyFile == "" {
				continue
			}
			key := c.CertFile + ":" + c.KeyFile
			if seen[key] {
				continue
			}
			seen[key] = true
			certs = append(certs, telemetry.CertInfo{
				CertName: c.Name,
				CertFile: c.CertFile,
				KeyFile:  c.KeyFile,
			})
		}
	}

	// Double-check with GlobalStore for any that might have been added dynamically
	gc := s.GlobalStore.Get(ctx)
	if gc != nil && gc.Tls != nil {
		for _, c := range gc.Tls.Certificates {
			if c.CertFile == "" || c.KeyFile == "" {
				continue
			}
			key := c.CertFile + ":" + c.KeyFile
			if seen[key] {
				continue
			}
			seen[key] = true
			certs = append(certs, telemetry.CertInfo{
				CertName: c.Name,
				CertFile: c.CertFile,
				KeyFile:  c.KeyFile,
			})
		}
	}

	return certs
}

// anyEntrypointTLS returns true if at least one entrypoint has TLS enabled.
func anyEntrypointTLS(epStore config.EntryPointStore) bool {
	for _, ep := range epStore.List(context.Background()) {
		if ep.Tls != nil && ep.Tls.Enabled {
			return true
		}
	}
	return false
}
