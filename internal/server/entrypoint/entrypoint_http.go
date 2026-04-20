package entrypoint

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/syncutil"
	"github.com/gsoultan/gateon/internal/telemetry"
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
	epLabel := cmp.Or(ep.Name, ep.Id)
	isMgmt := IsManagementAddress(ep.Address, deps)
	epHandler = injectEntryPointID(ep.Id, epLabel, isMgmt, epHandler)
	chain := []middleware.Middleware{
		middleware.RequestID(), // Added for global correlation
		middleware.Recovery(),
		middleware.SecurityHeaders(),
		middleware.Metrics("gateon-" + epLabel),
	}
	if ep.AccessLogEnabled {
		chain = append(chain, middleware.AccessLog("gateon-"+epLabel))
	}
	// Global per-IP connection limit to prevent Slowloris and basic DDOS.
	chain = append(chain, entrypointConnLimiter())

	// Final handler: wrap with monitoring, global rate limiter, and global CORS (for non-proxied requests).
	// For proxied requests, they use their own CORS policy from their route config if provided.
	finalEPHandler := middleware.Chain(chain...)(deps.Limiter.Handler(middleware.PerIP)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If it's a management or internal path, apply global CORS.
			// For user-defined routes, they handle their own CORS (avoid double headers).
			isMgmt, _ := r.Context().Value(middleware.IsManagementContextKey).(bool)
			if isMgmt || middleware.IsInternalPath(r.URL.Path) {
				deps.CORS.Handler(epHandler).ServeHTTP(w, r)
			} else {
				epHandler.ServeHTTP(w, r)
			}
		}),
	))
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
		Addr:      addr,
		Handler:   tcpHandler,
		TLSConfig: epTLSConfig,
		ErrorLog: logger.NewFilteredHandshakeLogger(logger.L, func(addr, err string) {
			telemetry.GlobalDiagnostics.RecordTLSError(ep.Id, addr, err)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(ep.ReadTimeoutMs) * time.Millisecond,
		WriteTimeout:      time.Duration(ep.WriteTimeoutMs) * time.Millisecond,
		IdleTimeout:       1 * time.Minute,
		MaxHeaderBytes:    1 << 20, // 1MB
		ConnState: func(conn net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				telemetry.GlobalDiagnostics.RecordConnection(ep.Id)
			case http.StateClosed, http.StateHijacked:
				telemetry.GlobalDiagnostics.RecordDisconnect(ep.Id)
			}
		},
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

func injectEntryPointID(epID, epLabel string, isMgmt bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, middleware.EntryPointIDContextKey, epID)
		ctx = context.WithValue(ctx, middleware.RouteNameContextKey, "gateon-"+epLabel)
		ctx = context.WithValue(ctx, middleware.IsManagementContextKey, isMgmt)

		// Log arrival for proxy traffic only
		if !isMgmt && !middleware.IsInternalPath(r.URL.Path) {
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

func entrypointConnLimiter() middleware.Middleware {
	maxStr := os.Getenv("GATEON_MAX_CONN_PER_IP")
	if maxStr == "" {
		// Default to 100 concurrent requests per IP if not set.
		// This is a safe default for most use cases but prevents basic Slowloris.
		return middleware.MaxConnectionsPerIP(100, middleware.PerIP)
	}
	max, _ := strconv.Atoi(maxStr)
	if max <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return middleware.MaxConnectionsPerIP(max, middleware.PerIP)
}
