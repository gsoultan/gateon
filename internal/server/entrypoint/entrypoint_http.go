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
	"golang.org/x/net/http2"
)

const (
	quicMaxIdleTimeout        = 30 * time.Second
	quicKeepAlivePeriod       = 10 * time.Second
	quicMaxIncomingStreams    = 1000
	quicMaxIncomingUniStreams = 500

	// HTTP/2 limits for the public entrypoint. Without explicit configuration the
	// public TLS server inherits Go's defaults; we pin them to bound per-connection
	// memory and reduce exposure to HTTP/2 stream-flood DoS (CVE-2023-44487
	// "Rapid Reset" class). The internal gRPC server caps streams separately.
	h2MaxConcurrentStreams = 250
	h2MaxReadFrameSize     = 1 << 18 // 256 KiB
	h2IdleTimeout          = 1 * time.Minute

	// defaultEntryPointTimeout is used when an entrypoint has no explicit
	// read/write timeout configured.
	defaultEntryPointTimeout = 15 * time.Second
)

// resolveEPTimeouts returns the current read and write timeouts for an
// entrypoint, always reading the latest values from the store so that
// configuration changes take effect immediately without a restart.
// It falls back to the snapshot ep and finally to sane defaults.
func resolveEPTimeouts(epID string, ep *gateonv1.EntryPoint, deps *Deps) (readTimeout, writeTimeout time.Duration) {
	readMs, writeMs := int32(0), int32(0)
	if ep != nil {
		readMs, writeMs = ep.ReadTimeoutMs, ep.WriteTimeoutMs
	}
	if deps != nil && deps.EpStore != nil {
		if latest, ok := deps.EpStore.Get(context.Background(), epID); ok && latest != nil {
			readMs, writeMs = latest.ReadTimeoutMs, latest.WriteTimeoutMs
		}
	}
	readTimeout = time.Duration(readMs) * time.Millisecond
	writeTimeout = time.Duration(writeMs) * time.Millisecond
	if readTimeout <= 0 {
		readTimeout = defaultEntryPointTimeout
	}
	if writeTimeout <= 0 {
		writeTimeout = defaultEntryPointTimeout
	}
	return readTimeout, writeTimeout
}

// dynamicTimeouts applies per-request read/write deadlines based on the live
// entrypoint configuration. Because deadlines are set per request via
// http.ResponseController (instead of baked into http.Server at startup),
// updates to ReadTimeoutMs/WriteTimeoutMs take effect on the next request
// without requiring a gateon restart.
func dynamicTimeouts(ep *gateonv1.EntryPoint, deps *Deps, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readTimeout, writeTimeout := resolveEPTimeouts(ep.Id, ep, deps)
		rc := http.NewResponseController(w)
		now := time.Now()
		if readTimeout > 0 {
			_ = rc.SetReadDeadline(now.Add(readTimeout))
		}
		if writeTimeout > 0 {
			_ = rc.SetWriteDeadline(now.Add(writeTimeout))
		}
		next.ServeHTTP(w, r)
	})
}

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
		middleware.RealIPGlobal(),
		middleware.RequestID(), // Added for global correlation
		middleware.Recovery(),
		middleware.SecurityHeaders(middleware.SecurityHeadersConfig{Preset: "recommended"}),
		middleware.HoneypotGlobal(deps.GlobalStore),
		middleware.GeoIPGlobal(deps.GlobalStore),
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
			logger.L.LogInfo("starting HTTP/3 (QUIC) entrypoint", "addr", addr)
			if err := h3Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.L.LogError("HTTP/3 server failed", "error", err, "addr", addr)
			}
		})
	}

	server := &http.Server{
		Addr: addr,
		// Read/write timeouts are applied per request via dynamicTimeouts so
		// configuration changes take effect immediately (no restart needed).
		// They are intentionally left unset on the server here.
		Handler:   dynamicTimeouts(ep, deps, tcpHandler),
		TLSConfig: epTLSConfig,
		ErrorLog: logger.NewFilteredHandshakeLogger(logger.L, func(addr, err string) {
			telemetry.GlobalDiagnostics.RecordTLSError(ep.Id, addr, err)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       1 * time.Minute,
		MaxHeaderBytes:    1 << 20, // 1MB
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, middleware.ConnContextKey, c)
		},
		ConnState: func(conn net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				telemetry.GlobalDiagnostics.RecordConnection(ep.Id)
			case http.StateClosed, http.StateHijacked:
				telemetry.GlobalDiagnostics.RecordDisconnect(ep.Id)
				// Clean up fingerprints when connection is closed
				middleware.RemoveFingerprints(conn)
			}
		},
	}
	// Explicitly bound HTTP/2 on the public TLS server (h2 is negotiated via ALPN
	// over TLS). This caps concurrent streams and frame size instead of relying on
	// Go's defaults, hardening against HTTP/2 stream-flood DoS.
	if epTLSConfig != nil {
		if err := http2.ConfigureServer(server, &http2.Server{
			MaxConcurrentStreams: h2MaxConcurrentStreams,
			MaxReadFrameSize:     h2MaxReadFrameSize,
			IdleTimeout:          h2IdleTimeout,
		}); err != nil {
			logger.L.LogError("failed to configure HTTP/2 limits", "error", err, "addr", addr)
		}
	}
	if deps.ShutdownRegistry != nil {
		deps.ShutdownRegistry.Register(server.Shutdown)
	}
	if hasTCP {
		if epTLSConfig != nil {
			logger.L.LogInfo("starting HTTPS entrypoint", "addr", addr, "type", ep.Type.String())
			if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.L.LogError("HTTPS server failed", "error", err, "addr", addr)
			}
		} else {
			logger.L.LogInfo("starting HTTP entrypoint", "addr", addr, "type", ep.Type.String())
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.L.LogError("HTTP server failed", "error", err, "addr", addr)
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
			logger.L.LogInfo("Proxy request received",
				"flow_step", "entrypoint_arrival",
				"request_id", request.GetID(r),
				"entrypoint", epID,
				"method", r.Method,
				"path", r.URL.Path)
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
