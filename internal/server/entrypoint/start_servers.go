// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package entrypoint

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/syncutil"
	"github.com/gsoultan/gateon/internal/telemetry"
	gtls "github.com/gsoultan/gateon/internal/tls"
	"github.com/gsoultan/gateon/pkg/l4"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// GATEON_ENTRYPOINT_RATE_LIMIT_QPS: per-IP requests per second (0 = disabled).
// GATEON_ENTRYPOINT_RATE_LIMIT_BURST: burst size (default 2x QPS).
// Aligned with Traefik: attach ratelimit middleware to routes for per-route limits.
func entrypointRateLimiter() middleware.RateLimiter {
	qpsStr := os.Getenv("GATEON_ENTRYPOINT_RATE_LIMIT_QPS")
	qps, _ := strconv.Atoi(qpsStr)
	if qps <= 0 {
		return middleware.NoopRateLimiter{}
	}
	burstStr := os.Getenv("GATEON_ENTRYPOINT_RATE_LIMIT_BURST")
	burst, _ := strconv.Atoi(burstStr)
	if burst <= 0 {
		burst = qps * 2
		if burst < 10 {
			burst = 10
		}
	}
	return middleware.NewQPSRateLimiter(qps, burst)
}

// StartServers starts all entrypoints (HTTP, TCP, UDP) in goroutines.
// shutdownReg is used for graceful shutdown; pass nil to skip registering shutdown.
// l4Resolver resolves L4 backends from Route->Service.
func StartServers(
	epStore config.EntryPointStore,
	port string,
	baseHandler http.Handler,
	wrapped GRPCWebHandler,
	tlsConfig *tls.Config,
	tlsManager gtls.TLSManager,
	wg *syncutil.WaitGroup,
	shutdownReg *ShutdownRegistry,
	l4_resolver L4Resolver,
	mgmt_config *gateonv1.ManagementConfig,
	global_store config.GlobalConfigStore,
	phantom PhantomCore,
) {
	limiter := entrypointRateLimiter()
	deps := &Deps{
		Port:             port,
		EpStore:          epStore,
		BaseHandler:      baseHandler,
		Wrapped:          wrapped,
		TLSConfig:        tlsConfig,
		TLSManager:       tlsManager,
		Limiter:          limiter,
		ShutdownRegistry: shutdownReg,
		L4Resolver:       l4_resolver,
		ManagementConfig: mgmt_config,
		GlobalStore:      global_store,
		Phantom:          phantom,
	}

	// ALWAYS start a dedicated management listener
	startSecureManagementServer(port, deps, wg)

	entryPoints := epStore.List(context.Background())
	for _, ep := range entryPoints {
		epCopy := ep
		runner := runnerFor(epCopy.Type)
		if runner == nil {
			continue
		}
		wg.Go(func() {
			runner.Run(context.Background(), epCopy, deps, wg)
		})
	}
}

func startSecureManagementServer(port string, deps *Deps, wg *syncutil.WaitGroup) {
	bind := "127.0.0.1"
	if deps.ManagementConfig != nil && deps.ManagementConfig.Bind != "" {
		bind = deps.ManagementConfig.Bind
	}
	if envBind := os.Getenv("GATEON_MANAGEMENT_BIND"); envBind != "" {
		bind = envBind
	}

	mgmtPort := port
	if deps.ManagementConfig != nil && deps.ManagementConfig.Port != "" {
		mgmtPort = deps.ManagementConfig.Port
	}
	if envPort := os.Getenv("GATEON_MANAGEMENT_PORT"); envPort != "" {
		mgmtPort = envPort
	}

	addr := net.JoinHostPort(bind, mgmtPort)

	// IP Whitelisting for management entrypoint
	allowedIPs := []string{"127.0.0.1", "::1"}
	if deps.ManagementConfig != nil && len(deps.ManagementConfig.AllowedIps) > 0 {
		allowedIPs = deps.ManagementConfig.AllowedIps
	}
	if allowedIPsStr := os.Getenv("GATEON_MANAGEMENT_ALLOWED_IPS"); allowedIPsStr != "" {
		allowedIPs = strings.Split(allowedIPsStr, ",")
	}

	mgmtHost := ""
	if bind != "0.0.0.0" && bind != "::" && net.ParseIP(bind) == nil {
		mgmtHost = bind
	}
	if envHost := os.Getenv("GATEON_MANAGEMENT_HOST"); envHost != "" {
		mgmtHost = envHost
	}

	handler := middleware.Chain(
		middleware.EntryPoint("management", "management", true),
		middleware.Recovery(),
		middleware.SecurityHeaders(middleware.SecurityHeadersConfig{Preset: "recommended"}),
		middleware.HostFilter(mgmtHost),
		middleware.IPFilter(allowedIPs, nil),
		middleware.MaxConnections(500),
	)(deps.BaseHandler)

	// Enable H2C (HTTP/2 Cleartext) support for gRPC and modern HTTP clients.
	// In Go 1.26+, this is handled natively via the Protocols field.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	server := &http.Server{
		Addr:      addr,
		Handler:   handler,
		HTTP2:     &http.HTTP2Config{},
		Protocols: protocols,
		ErrorLog: logger.NewFilteredHandshakeLogger(logger.L, func(addr, err string) {
			telemetry.GlobalDiagnostics.RecordTLSError("management", addr, err)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       1 * time.Minute,
		MaxHeaderBytes:    1 << 20, // 1MB
		ConnState: func(conn net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				telemetry.GlobalDiagnostics.RecordConnection("management")
			case http.StateClosed, http.StateHijacked:
				telemetry.GlobalDiagnostics.RecordDisconnect("management")
			}
		},
	}

	if deps.ShutdownRegistry != nil {
		deps.ShutdownRegistry.Register(func(context.Context) error {
			return server.Shutdown(context.Background())
		})
	}

	logger.L.LogInfo("Secure Management Entrypoint started", "addr", addr)
	wg.Go(func() {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			logger.L.LogError("Management listen failed", "error", err)
			return
		}
		defer l.Close()

		if deps.Phantom != nil {
			l = deps.Phantom.OptimizeListener(l)
		}

		if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.L.LogError("Management server failed", "error", err)
		}
	})
}

func startTCPServer(addr string, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup, shutdownReg *ShutdownRegistry) {
	logger.L.Info().Str("addr", addr).Str("ep", ep.Id).Msg("starting TCP entrypoint")
	var l net.Listener
	var err error
	if ep.Tls != nil && ep.Tls.Enabled && deps.TLSConfig != nil {
		l, err = tls.Listen("tcp", addr, deps.TLSConfig)
	} else {
		l, err = net.Listen("tcp", addr)
	}
	if err != nil {
		logger.L.LogError("TCP listen failed", "error", err, "addr", addr)
		return
	}
	if shutdownReg != nil {
		shutdownReg.Register(func(context.Context) error {
			return l.Close()
		})
	}
	wg.Go(func() {
		defer l.Close()
		plaintext := deps.TLSConfig == nil
		for {
			conn, err := l.Accept()
			if err != nil {
				telemetry.GlobalDiagnostics.RecordEPError(ep.Id, err.Error())
				return
			}
			telemetry.GlobalDiagnostics.RecordConnection(ep.Id)
			c := conn
			if plaintext {
				wg.Go(func() {
					defer telemetry.GlobalDiagnostics.RecordDisconnect(ep.Id)
					if deps.Phantom != nil {
						// For plaintext TCP, attempt TITAN L4 hardware offload (AF_XDP/io_uring)
						if err := deps.Phantom.ProxyL4(context.Background(), c, ""); err == nil {
							return
						}
					}
					handleTCPConnWithInspection(c, ep, deps, wg)
				})
			} else {
				var p l4.TCPProxy
				if deps.L4Resolver != nil {
					p = deps.L4Resolver.ResolveTCP(ep, "")
				}
				wg.Go(func() {
					defer telemetry.GlobalDiagnostics.RecordDisconnect(ep.Id)
					defer c.Close()
					if p != nil {
						handleTCPProxyL4(c, p)
					} else {
						handleTCPConn(c)
					}
				})
			}
		}
	})
}

func startUDPServer(addr string, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup, shutdownReg *ShutdownRegistry) {
	logger.L.LogInfo("starting UDP entrypoint", "addr", addr)
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logger.L.LogError("UDP resolve failed", "error", err, "addr", addr)
		return
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		logger.L.LogError("UDP listen failed", "error", err, "addr", addr)
		return
	}
	if shutdownReg != nil {
		shutdownReg.Register(func(context.Context) error {
			return conn.Close()
		})
	}
	var proxy l4.UDPProxy
	if deps.L4Resolver != nil {
		proxy = deps.L4Resolver.ResolveUDP(ep)
	}
	wg.Go(func() {
		defer conn.Close()
		if proxy != nil {
			handleUDPProxyL4(conn, proxy)
		} else {
			handleUDPConn(conn)
		}
	})
}

var (
	peekPool = sync.Pool{
		New: func() any {
			b := make([]byte, PeekSize)
			return &b
		},
	}
)

func handleTCPConnWithInspection(conn net.Conn, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup) {
	logger.L.LogDebug("TCP connection received for inspection", "ep", ep.Id, "remote", conn.RemoteAddr().String())

	// Use a shorter deadline for the first byte, then a longer one for the rest
	// to avoid blocking goroutines for slow/idle connections.
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	peekPtr := peekPool.Get().(*[]byte)
	peek := *peekPtr
	defer peekPool.Put(peekPtr)

	// Read at least 1 byte to detect protocol early
	n, err := conn.Read(peek)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			// No data received within 1s, handle as generic TCP
			_ = conn.SetReadDeadline(time.Time{})
			goto fallback
		}
		logger.L.LogError("TCP inspection initial read error", "ep", ep.Id, "error", err)
		_ = conn.Close()
		return
	}

	// If we got some data, try to read more if needed for HTTP/2 detection (24 bytes)
	if n > 0 && n < PeekSize {
		// If it looks like HTTP/2 preface start, try to read more
		if peek[0] == 'P' || IsTCPAppHTTP(peek[:n]) {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n2, _ := io.ReadAtLeast(conn, peek[n:], 0) // non-blocking best-effort
			n += n2
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	if n > 0 {
		peeked := make([]byte, n)
		copy(peeked, peek[:n])

		if IsTCPAppHTTP(peeked) {
			logger.L.LogDebug("TCP inspection: HTTP detected", "ep", ep.Id)
			serveConnAsHTTP(conn, peeked, ep, deps)
			return
		}

		protocol := ""
		if IsSSH(peeked) {
			protocol = "ssh"
			logger.L.Info().Str("ep", ep.Id).Str("remote", conn.RemoteAddr().String()).Msg("SSH protocol detected on TCP entrypoint")
		} else if IsRDP(peeked) {
			protocol = "rdp"
			logger.L.Info().Str("ep", ep.Id).Str("remote", conn.RemoteAddr().String()).Msg("RDP protocol detected on TCP entrypoint")
		}

		var p l4.TCPProxy
		if deps.L4Resolver != nil {
			p = deps.L4Resolver.ResolveTCP(ep, protocol)
		}
		if p != nil {
			logger.L.LogInfo("TCP inspection: Route found, proxying", "ep", ep.Id, "protocol", protocol)
			handleTCPProxyL4(newPeekedConn(conn, peeked), p)
			return
		}
	}

fallback:
	// No protocol detected or no route found
	var peeked []byte
	if n > 0 {
		peeked = make([]byte, n)
		copy(peeked, peek[:n])
	}
	logger.L.LogDebug("TCP inspection fallback to generic TCP", "ep", ep.Id, "bytes", n)
	pc := newPeekedConn(conn, peeked)
	handleTCPConn(pc)
	_ = pc.Close()
}

func handleTCPConn(conn net.Conn) {
	_, _ = fmt.Fprintf(conn, "Gateon TCP Entrypoint - %s\n", time.Now().String())
}

func handleTCPProxyL4(client net.Conn, pool l4.TCPProxy) {
	pool.ProxyTCP(context.Background(), client)
}

func handleUDPConn(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		logger.L.Debug().Str("addr", addr.String()).Int("bytes", n).Msg("received UDP packet")
	}
}

func handleUDPProxyL4(conn *net.UDPConn, proxy l4.UDPProxy) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Copy data: HandlePacket may write async; buffer is reused next iteration.
		packet := make([]byte, n)
		copy(packet, buf[:n])
		proxy.HandlePacket(conn, addr, packet)
	}
}

func IsManagementAddress(addr string, deps *Deps) bool {
	mgmtAddr := GetManagementAddr(deps.Port, deps.ManagementConfig)
	return normalizeAddr(addr) == normalizeAddr(mgmtAddr)
}

func GetManagementAddr(defaultPort string, config *gateonv1.ManagementConfig) string {
	bind := "127.0.0.1"
	if config != nil && config.Bind != "" {
		bind = config.Bind
	}
	if envBind := os.Getenv("GATEON_MANAGEMENT_BIND"); envBind != "" {
		bind = envBind
	}

	mgmtPort := defaultPort
	if config != nil && config.Port != "" {
		mgmtPort = config.Port
	}
	if envPort := os.Getenv("GATEON_MANAGEMENT_PORT"); envPort != "" {
		mgmtPort = envPort
	}

	return net.JoinHostPort(bind, mgmtPort)
}

func normalizeAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "*"
	}
	return net.JoinHostPort(host, port)
}
