package entrypoint

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gateon/gateon/internal/logger"
	"github.com/gateon/gateon/internal/middleware"
	"github.com/gateon/gateon/internal/syncutil"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/quic-go/quic-go/http3"
)

type httpRunner struct{}

func (*httpRunner) Run(ctx context.Context, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup) {
	addr := ep.Address
	if addr == "" {
		return
	}
	hasTCP, hasUDP := protocols(ep)
	var epHandler http.Handler = deps.BaseHandler
	switch ep.Type {
	case gateonv1.EntryPoint_HTTP, gateonv1.EntryPoint_HTTP2, gateonv1.EntryPoint_GRPC:
		epHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			isGRPC := (r.ProtoMajor == 2 || r.ProtoMajor == 3) && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
			isGRPCWeb := deps.Wrapped.IsGrpcWebRequest(r) || deps.Wrapped.IsAcceptableGrpcCorsRequest(r) || deps.Wrapped.IsGrpcWebSocketRequest(r)
			if (ep.Type == gateonv1.EntryPoint_HTTP2 || ep.Type == gateonv1.EntryPoint_GRPC) && (isGRPC || isGRPCWeb) {
				deps.Wrapped.ServeHTTP(w, r)
				return
			}
			deps.BaseHandler.ServeHTTP(w, r)
		})
	case gateonv1.EntryPoint_HTTP3:
		epHandler = deps.BaseHandler
	}
	epHandler = injectEntryPointID(ep.Id, epHandler)
	chain := []middleware.Middleware{middleware.Metrics("gateon-" + ep.Id)}
	if ep.AccessLogEnabled {
		chain = append(chain, middleware.AccessLog("gateon-"+ep.Id))
	}
	finalEPHandler := middleware.Chain(chain...)(deps.CORS.Handler(deps.Limiter.Handler(middleware.PerIP)(epHandler)))
	var epTLSConfig *tls.Config
	if ep.Tls != nil && ep.Tls.Enabled {
		epTLSConfig = deps.TLSConfig.Clone()
	}
	finalEPHandler = deps.TLSManager.HTTPChallengeHandler(finalEPHandler)
	server := &http.Server{
		Addr:              addr,
		Handler:           finalEPHandler,
		TLSConfig:         epTLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(ep.ReadTimeoutMs) * time.Millisecond,
		WriteTimeout:      time.Duration(ep.WriteTimeoutMs) * time.Millisecond,
	}
	if server.ReadTimeout == 0 {
		server.ReadTimeout = 15 * time.Second
	}
	if server.WriteTimeout == 0 {
		server.WriteTimeout = 15 * time.Second
	}
	if deps.ShutdownRegistry != nil {
		deps.ShutdownRegistry.Register(server.Shutdown)
	}
	if hasTCP {
		if epTLSConfig != nil {
			logger.L.Info().Str("addr", addr).Str("type", ep.Type.String()).Msg("starting HTTPS entrypoint")
			if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.L.Error().Err(err).Str("addr", addr).Msg("HTTPS server failed")
			}
		} else {
			logger.L.Info().Str("addr", addr).Str("type", ep.Type.String()).Msg("starting HTTP entrypoint")
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.L.Error().Err(err).Str("addr", addr).Msg("HTTP server failed")
			}
		}
	}
	if ep.Type == gateonv1.EntryPoint_HTTP3 && hasUDP && epTLSConfig != nil {
		logger.L.Info().Str("addr", addr).Msg("starting HTTP/3 entrypoint")
		h3Server := &http3.Server{Addr: addr, Handler: finalEPHandler, TLSConfig: epTLSConfig}
		if deps.ShutdownRegistry != nil {
			deps.ShutdownRegistry.Register(func(ctx context.Context) error {
				return h3Server.Close()
			})
		}
		origHandler := server.Handler
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = h3Server.SetQUICHeaders(w.Header())
			origHandler.ServeHTTP(w, r)
		})
		if err := h3Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.L.Error().Err(err).Str("addr", addr).Msg("HTTP/3 server failed")
		}
	}
}

func injectEntryPointID(epID string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, middleware.EntryPointIDContextKey, epID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func protocols(ep *gateonv1.EntryPoint) (hasTCP, hasUDP bool) {
	if len(ep.Protocols) == 0 {
		switch {
		case ep.Type == gateonv1.EntryPoint_HTTP3:
			return true, true
		case ep.Protocol == gateonv1.EntryPoint_UDP_PROTO || ep.Type == gateonv1.EntryPoint_UDP:
			return false, true
		default:
			return true, false
		}
	}
	for _, p := range ep.Protocols {
		if p == gateonv1.EntryPoint_TCP_PROTO {
			hasTCP = true
		} else if p == gateonv1.EntryPoint_UDP_PROTO {
			hasUDP = true
		}
	}
	return hasTCP, hasUDP
}
