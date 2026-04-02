package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/ai"
	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/server/entrypoint"
	"github.com/gsoultan/gateon/internal/server/handlers"
	"github.com/gsoultan/gateon/internal/syncutil"
	"github.com/gsoultan/gateon/internal/telemetry"
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
	apiService := api.NewApiService(api.ApiServiceConfig{
		Version:     s.Version,
		Routes:      s.RouteStore,
		Services:    s.ServiceStore,
		Globals:     s.GlobalStore,
		EntryPoints: s.EpStore,
		Middlewares: s.MwStore,
		TLSOptions:  s.TLSOptStore,
		Auth:        s.AuthManager,
	})

	var wg syncutil.WaitGroup
	l4Resolver := l4.NewResolver(s.RouteStore, s.ServiceStore)
	proxyInvalidator := NewServerProxyInvalidator(s, l4Resolver, s.RouteStore)
	if s.RedisClient != nil {
		proxyInvalidator = NewDistributedProxyInvalidator(proxyInvalidator, s.RedisClient)
		wg.Go(func() {
			StartInvalidationListener(ctx, proxyInvalidator, s.RedisClient)
		})
	}
	routeService := domain.NewRouteService(s.RouteStore, proxyInvalidator)
	serviceService := domain.NewServiceService(s.ServiceStore, s.RouteStore, proxyInvalidator)
	epService := domain.NewEntryPointService(s.EpStore)
	mwFactory := middleware.NewFactory(s.RedisClient, s.GlobalStore)
	mwService := domain.NewMiddlewareServiceWithOptions(s.MwStore, s.RouteStore, proxyInvalidator, mwFactory, middleware.WAFCacheInvalidator{})
	tlsOptService := domain.NewTLSOptionService(s.TLSOptStore, s.RouteStore, proxyInvalidator)
	canaryService := domain.NewCanaryService(serviceService)
	aiService := ai.NewAIService(s.GlobalStore, s.RouteStore, s.ServiceStore)

	grpcServer := grpc.NewServer(grpc.MaxConcurrentStreams(10000))
	gateonv1.RegisterApiServiceServer(grpcServer, apiService)
	gateonv1.RegisterAIServiceServer(grpcServer, aiService)
	// Internal API only: gRPC-Web for the dashboard. Allow all origins; auth protects the API.
	// User routes use the grpcweb middleware with per-route allowed_origins config.
	internalAPI := grpcweb.WrapServer(grpcServer, grpcweb.WithOriginFunc(func(string) bool { return true }))
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
		AIService:          aiService,
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
	c := BuildCORS()
	tlsManager := CreateTLSManager(s)
	tlsConfig, err := tlsManager.GetTLSConfig()
	if err != nil {
		logger.L.Fatal().Err(err).Msg("failed to initialize tls")
	}
	// When global TLS is not explicitly enabled but at least one entrypoint
	// has TLS turned on, create a minimal TLS config so that SNI can
	// dynamically serve per-route certificates.
	if tlsConfig == nil && anyEntrypointTLS(s.EpStore) {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		}
		logger.L.Info().Msg("created base TLS config for entrypoint-level TLS (global TLS not enabled)")
	}
	SetupSNI(tlsConfig, tlsManager, SNIDeps{
		RouteStore:  s.RouteStore,
		GlobalStore: s.GlobalStore,
		TLSOptStore: s.TLSOptStore,
	})

	shutdownReg := &entrypoint.ShutdownRegistry{}
	var mgmtConfig *gateonv1.ManagementConfig
	if gc := s.GlobalStore.Get(ctx); gc != nil {
		mgmtConfig = gc.Management
	}
	entrypoint.StartServers(s.EpStore, s.Port, baseHandler, internalAPI, tlsConfig, tlsManager, c, &wg, shutdownReg, entrypoint.WrapL4Resolver(l4Resolver), mgmtConfig)
	// Initialize metrics subsystem
	telemetry.InitStartTime()
	metricsStop := make(chan struct{})
	telemetry.StartSystemMetricsCollector(metricsStop)

	// Start TLS certificate expiry monitoring
	certInfos := collectCertInfos(ctx, s)
	telemetry.StartTLSCertMonitor(certInfos, metricsStop)

	logger.L.Info().Str("port", s.Port).Msg("Gateon API Gateway started")

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
	logger.L.Info().Msg("shutting down gracefully")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()
	shutdownReg.ShutdownAll(shutdownCtx)
	grpcServer.GracefulStop()
	if s.RedisClient != nil {
		if closer, ok := s.RedisClient.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
	close(metricsStop)
	wg.Wait()
	logger.L.Info().Msg("shutdown complete")
}

// collectCertInfos gathers TLS certificate info from global TLS config for expiry monitoring.
func collectCertInfos(ctx context.Context, s *Server) []telemetry.CertInfo {
	var certs []telemetry.CertInfo
	seen := make(map[string]bool)

	gc := s.GlobalStore.Get(ctx)
	if gc == nil || gc.Tls == nil {
		return certs
	}

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
