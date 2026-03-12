package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gateon/gateon/internal/api"
	"github.com/gateon/gateon/internal/config"
	"github.com/gateon/gateon/internal/logger"
	"github.com/gateon/gateon/internal/server/entrypoint"
	"github.com/gateon/gateon/internal/server/handlers"
	"github.com/gateon/gateon/internal/syncutil"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"google.golang.org/grpc"
)

// ShutdownTimeout is the maximum time to wait for servers to shut down gracefully.
const ShutdownTimeout = 30 * time.Second

// Run starts the gateway: gRPC server, REST mux, base handler, entrypoints, and proxy sync loop.
// It blocks until ctx is cancelled, then shuts down all servers gracefully and returns.
// globalReg is used for TLS and base handler auth.
func Run(ctx context.Context, s *Server, uiHandler http.Handler, globalReg *config.GlobalRegistry) {
	apiService := &api.ApiService{
		Version:     s.Version,
		Routes:      s.RouteReg,
		Services:    s.ServiceReg,
		Globals:     globalReg,
		EntryPoints: s.EpReg,
		Middlewares: s.MwReg,
		TLSOptions:  s.TLSOptReg,
		Auth:        s.AuthManager,
	}
	grpcServer := grpc.NewServer(grpc.MaxConcurrentStreams(1024))
	gateonv1.RegisterApiServiceServer(grpcServer, apiService)
	wrapped := grpcweb.WrapServer(grpcServer, grpcweb.WithOriginFunc(func(string) bool { return true }))
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, apiService, &handlers.Deps{
		RouteReg:              s.RouteReg,
		ServiceReg:            s.ServiceReg,
		EpReg:                 s.EpReg,
		MwReg:                 s.MwReg,
		TLSOptReg:             s.TLSOptReg,
		InvalidateRouteProxy:  s.InvalidateRouteProxy,
		InvalidateRouteProxies: s.InvalidateRouteProxies,
		AuthManager:          s.AuthManager,
		Version:               s.Version,
		StartTime:             s.StartTime(),
	})

	baseHandler := CreateBaseHandler(uiHandler, s, globalReg, apiService, wrapped, mux)
	c := BuildCORS()
	tlsManager := CreateTLSManager(globalReg)
	tlsConfig, err := tlsManager.GetTLSConfig()
	if err != nil {
		logger.L.Fatal().Err(err).Msg("failed to initialize tls")
	}
	SetupSNI(tlsConfig, tlsManager, s)

	shutdownReg := &entrypoint.ShutdownRegistry{}
	var wg syncutil.WaitGroup
	entrypoint.StartServers(s.EpReg, s.Port, baseHandler, wrapped, tlsConfig, tlsManager, c, &wg, shutdownReg)
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
	wg.Wait()
	logger.L.Info().Msg("shutdown complete")
}
