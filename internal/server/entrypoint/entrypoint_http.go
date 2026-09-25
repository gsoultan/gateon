// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/middleware/security"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/middleware/traffic"
	"github.com/gsoultan/gateon/internal/middleware/transform"
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
		// Skip deadlines for long-lived connections (WebSocket and SSE)
		if r.Header.Get("Upgrade") != "" ||
			strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream") {
			next.ServeHTTP(w, r)
			return
		}

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

// entrypointChain is what every request on an HTTP entrypoint passes through
// before it is routed.
//
// It sets no security headers. It used to apply the "recommended" preset here,
// to every response -- so every proxied page that did not send its own CSP got
// the gateway's, which was written for the dashboard: script-src 'self' with a
// nonce no backend can know (inline and CDN scripts blocked), fonts and images
// from its own origin only, form-action 'self' (a login form posting to an
// identity provider blocked), frame-ancestors 'none', and HSTS with
// includeSubDomains pinning every subdomain to HTTPS for a year. The dashboard
// and management API apply their own headers in BaseHandler; a route that wants
// headers on its backend's responses attaches a security_headers middleware.
func entrypointChain(ctx context.Context, ep *gateonv1.EntryPoint, deps *Deps) []middleware.Middleware {
	epLabel := cmp.Or(ep.Name, ep.Id)
	chain := []middleware.Middleware{
		transform.GlobalCORS(),
		middleware.EntryPoint(ep.Id, epLabel, IsManagementAddress(ep.Address, deps)),
		middleware.Metrics("gateon-" + epLabel),
		identity.IPMitigation(),
		identity.UserMitigation(),
		middleware.Recovery(),
		security.HoneypotGlobal(deps.GlobalStore),
		security.GeoIPGlobal(ctx, deps.GlobalStore),
	}
	if ep.AccessLogEnabled {
		chain = append(chain, middleware.AccessLog("gateon-"+epLabel))
	}
	// Global per-IP connection limit to prevent Slowloris and basic DDOS.
	return append(chain, entrypointConnLimiter())
}

type httpRunner struct{}

func (*httpRunner) Run(ctx context.Context, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup) {
	if ep.Address == "" {
		return
	}
	e := &httpEntrypoint{ep: ep, deps: deps, wg: wg}
	if ep.Tls != nil && ep.Tls.Enabled {
		e.tlsConfig = deps.TLSConfig.Clone()
	}
	server := e.newServer(dynamicTimeouts(ep, deps, e.startHTTP3(e.frontHandler(ctx))))
	if deps.ShutdownRegistry != nil {
		deps.ShutdownRegistry.Register(func(ctx context.Context) error {
			return shutdownHTTPServer(ctx, server)
		})
	}
	if hasTCP, _ := protocols(ep); hasTCP {
		e.serveTCP(server)
	}
}

// httpEntrypoint is what Run's steps share for one entrypoint.
type httpEntrypoint struct {
	ep        *gateonv1.EntryPoint
	deps      *Deps
	wg        *syncutil.WaitGroup
	tlsConfig *tls.Config
}

// frontHandler is the entrypoint chain around the base handler and the global
// rate limiter. CORS is handled at the route level for proxy traffic, and in
// BaseHandler for internal traffic.
func (e *httpEntrypoint) frontHandler(ctx context.Context) http.Handler {
	ep, deps := e.ep, e.deps
	h := middleware.Chain(entrypointChain(ctx, ep, deps)...)(deps.Limiter.Handler(traffic.PerIP)(deps.BaseHandler))

	// tls.auto_redirect: send plaintext traffic to the TLS entrypoint. Inserted
	// here, *inside* the ACME wrapper below, so the HTTP-01 challenge still
	// answers on port 80 — redirecting the challenge would break certificate
	// issuance for the very entrypoint being redirected to.
	isMgmt := IsManagementAddress(ep.Address, deps)
	if port := httpsRedirectTargetFor(ctx, deps); shouldRedirectToHTTPS(ep, isMgmt, autoRedirectEnabled(ctx, deps), port) {
		h = httpsRedirect(port)
		logger.L.LogInfo("entrypoint redirects plaintext traffic to HTTPS",
			"entrypoint", ep.Id, "address", ep.Address, "target_port", port)
	}
	return deps.TLSManager.HTTPChallengeHandler(h)
}

// startHTTP3 starts HTTP/3 (QUIC) beside TCP when the entrypoint is configured
// for it, and returns the TCP handler, which then advertises HTTP/3 to HTTP/1
// and HTTP/2 clients.
func (e *httpEntrypoint) startHTTP3(h http.Handler) http.Handler {
	_, hasUDP := protocols(e.ep)
	if e.ep.Type != gateonv1.EntryPoint_HTTP3 || !hasUDP || e.tlsConfig == nil {
		return h
	}
	addr := e.ep.Address
	h3Server := newHTTP3Server(addr, h, e.tlsConfig)
	if e.deps.ShutdownRegistry != nil {
		e.deps.ShutdownRegistry.Register(func(ctx context.Context) error {
			return h3Server.Close()
		})
	}
	e.wg.Go(func() {
		logger.L.LogInfo("starting HTTP/3 (QUIC) entrypoint", "addr", addr)
		if err := h3Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.L.LogError("HTTP/3 server failed", "error", err, "addr", addr)
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor < 3 {
			_ = h3Server.SetQUICHeaders(w.Header())
		}
		h.ServeHTTP(w, r)
	})
}

// newServer builds the TCP server with every limit set explicitly. H2C
// (HTTP/2 cleartext) is enabled for gRPC and modern HTTP clients through the
// Protocols field.
func (e *httpEntrypoint) newServer(h http.Handler) *http.Server {
	ep := e.ep
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	if e.tlsConfig != nil {
		protocols.SetHTTP2(true)
	}
	server := &http.Server{
		Addr:      ep.Address,
		Handler:   h,
		TLSConfig: e.tlsConfig,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: h2MaxConcurrentStreams,
			MaxReadFrameSize:     h2MaxReadFrameSize,
		},
		Protocols: protocols,
		ErrorLog: logger.NewFilteredHandshakeLogger(logger.L, func(addr, err string) {
			telemetry.GlobalDiagnostics.RecordTLSError(ep.Id, addr, err)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       1 * time.Minute,
		MaxHeaderBytes:    1 << 20, // 1MB
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, identity.ConnContextKey, c)
		},
		ConnState: func(conn net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				telemetry.GlobalDiagnostics.RecordConnection(ep.Id)
			case http.StateClosed, http.StateHijacked:
				telemetry.GlobalDiagnostics.RecordDisconnect(ep.Id)
				// Clean up fingerprints when connection is closed
				identity.RemoveFingerprints(conn)
			}
		},
	}
	// Explicitly bound HTTP/2 on the public TLS server (h2 is negotiated via ALPN
	// over TLS). This caps concurrent streams and frame size instead of relying on
	// Go's defaults, hardening against HTTP/2 stream-flood DoS.
	if e.tlsConfig != nil {
		if err := http2.ConfigureServer(server, &http2.Server{
			MaxConcurrentStreams: h2MaxConcurrentStreams,
			MaxReadFrameSize:     h2MaxReadFrameSize,
			IdleTimeout:          h2IdleTimeout,
		}); err != nil {
			logger.L.LogError("failed to configure HTTP/2 limits", "error", err, "addr", ep.Address)
		}
	}
	return server
}

// serveTCP listens on the entrypoint's address and serves, over TLS when the
// entrypoint has it.
func (e *httpEntrypoint) serveTCP(server *http.Server) {
	addr := e.ep.Address
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logger.L.LogError("HTTP/S listen failed", "error", err, "addr", addr)
		return
	}
	if e.deps.Phantom != nil {
		l = e.deps.Phantom.OptimizeListener(l)
	}
	if e.tlsConfig != nil {
		logger.L.LogInfo("starting HTTPS entrypoint", "addr", addr, "type", e.ep.Type.String())
		e.wg.Go(func() {
			if err := server.ServeTLS(l, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.L.LogError("HTTPS server failed", "error", err, "addr", addr)
			}
		})
		return
	}
	logger.L.LogInfo("starting HTTP entrypoint", "addr", addr, "type", e.ep.Type.String())
	e.wg.Go(func() {
		if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.L.LogError("HTTP server failed", "error", err, "addr", addr)
		}
	})
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
		switch p {
		case gateonv1.EntryPoint_TCP_PROTO:
			hasTCP = true
		case gateonv1.EntryPoint_UDP_PROTO:
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
		return traffic.MaxConnectionsPerIP(100, traffic.PerIP)
	}
	max, _ := strconv.Atoi(maxStr)
	if max <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return traffic.MaxConnectionsPerIP(max, traffic.PerIP)
}
