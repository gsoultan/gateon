package entrypoint

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/syncutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	quicMaxIdleTimeout        = 30 * time.Second
	quicKeepAlivePeriod       = 10 * time.Second
	quicMaxIncomingStreams    = 1000
	quicMaxIncomingUniStreams = 500
)

type httpRunner struct{}

func (*httpRunner) Run(ctx context.Context, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup) {
	addr := ep.Address
	if addr == "" {
		return
	}
	hasTCP, hasUDP := protocols(ep)
	var epHandler http.Handler = deps.BaseHandler
	isMgmt := IsManagementAddress(ep.Address, deps)
	epHandler = injectEntryPointID(ep.Id, isMgmt, epHandler)
	chain := []middleware.Middleware{
		middleware.RequestID(), // Added for global correlation
		middleware.Recovery(),
		middleware.Metrics("gateon-" + ep.Id),
	}
	if ep.AccessLogEnabled {
		chain = append(chain, middleware.AccessLog("gateon-"+ep.Id))
	}
	finalEPHandler := middleware.Chain(chain...)(deps.CORS.Handler(deps.Limiter.Handler(middleware.PerIP)(epHandler)))
	var epTLSConfig *tls.Config
	if ep.Tls != nil && ep.Tls.Enabled {
		epTLSConfig = deps.TLSConfig.Clone()
	}
	finalEPHandler = deps.TLSManager.HTTPChallengeHandler(finalEPHandler)

	// Start HTTP/3 (QUIC) in parallel with TCP when configured — production-ready settings.
	needH3 := ep.Type == gateonv1.EntryPoint_HTTP3 && hasUDP && epTLSConfig != nil
	var tcpHandler http.Handler = finalEPHandler
	if needH3 {
		h3Server := newHTTP3Server(addr, finalEPHandler, epTLSConfig)
		tcpHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor < 3 {
				_ = h3Server.SetQUICHeaders(w.Header())
			}
			finalEPHandler.ServeHTTP(w, r)
		})
		if deps.ShutdownRegistry != nil {
			deps.ShutdownRegistry.Register(func(ctx context.Context) error {
				return h3Server.Close()
			})
		}
		wg.Go(func() {
			logger.L.Info().Str("addr", addr).Msg("starting HTTP/3 (QUIC) entrypoint")
			if err := h3Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.L.Error().Err(err).Str("addr", addr).Msg("HTTP/3 server failed")
			}
		})
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           tcpHandler,
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
}

func newHTTP3Server(addr string, handler http.Handler, tlsConfig *tls.Config) *http3.Server {
	return &http3.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsConfig,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:        quicMaxIdleTimeout,
			KeepAlivePeriod:       quicKeepAlivePeriod,
			MaxIncomingStreams:    quicMaxIncomingStreams,
			MaxIncomingUniStreams: quicMaxIncomingUniStreams,
		},
	}
}

func injectEntryPointID(epID string, isMgmt bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, middleware.EntryPointIDContextKey, epID)
		ctx = context.WithValue(ctx, middleware.IsManagementContextKey, isMgmt)

		// Log arrival for proxy traffic only
		if !isMgmt && !isInternalPath(r.URL.Path) {
			logger.L.Info().
				Str("flow_step", "entrypoint_arrival").
				Str("request_id", request.GetID(r)).
				Str("entrypoint", epID).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Msg("Proxy request received")
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isInternalPath(path string) bool {
	return strings.HasPrefix(path, "/v1/") || path == "/metrics" || path == "/healthz" || path == "/readyz"
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
