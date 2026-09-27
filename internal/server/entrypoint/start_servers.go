// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
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
	"github.com/gsoultan/gateon/internal/middleware/security"
	"github.com/gsoultan/gateon/internal/middleware/traffic"
	"github.com/gsoultan/gateon/internal/syncutil"
	"github.com/gsoultan/gateon/internal/telemetry"
	gtls "github.com/gsoultan/gateon/internal/tls"
	"github.com/gsoultan/gateon/pkg/l4"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// GATEON_ENTRYPOINT_RATE_LIMIT_QPS: per-IP requests per second (0 = disabled).
// GATEON_ENTRYPOINT_RATE_LIMIT_BURST: burst size (default 2x QPS).
// Aligned with Traefik: attach ratelimit middleware to routes for per-route limits.
func entrypointRateLimiter() traffic.RateLimiter {
	qpsStr := os.Getenv("GATEON_ENTRYPOINT_RATE_LIMIT_QPS")
	qps, _ := strconv.Atoi(qpsStr)
	if qps <= 0 {
		return traffic.NoopRateLimiter{}
	}
	burstStr := os.Getenv("GATEON_ENTRYPOINT_RATE_LIMIT_BURST")
	burst, _ := strconv.Atoi(burstStr)
	if burst <= 0 {
		burst = qps * 2
		if burst < 10 {
			burst = 10
		}
	}
	return traffic.NewQPSRateLimiter(qps, burst)
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

// ManagementBind is the address the dedicated management listener binds to:
// GATEON_MANAGEMENT_BIND, else the configured bind, else loopback.
func ManagementBind(cfg *gateonv1.ManagementConfig) string {
	if envBind := os.Getenv("GATEON_MANAGEMENT_BIND"); envBind != "" {
		return envBind
	}
	if bind := cfg.GetBind(); bind != "" {
		return bind
	}
	return loopbackIPv4
}

// loopbackIPv4 is where the management listener binds, and whom it admits, when
// nothing says otherwise.
const loopbackIPv4 = "127.0.0.1"

// ManagementAllowedIPs is the client allowlist the dedicated management
// listener enforces: GATEON_MANAGEMENT_ALLOWED_IPS, else the configured list,
// else loopback only.
func ManagementAllowedIPs(cfg *gateonv1.ManagementConfig) []string {
	if allowedIPsStr := os.Getenv("GATEON_MANAGEMENT_ALLOWED_IPS"); allowedIPsStr != "" {
		return strings.Split(allowedIPsStr, ",")
	}
	if allowed := cfg.GetAllowedIps(); len(allowed) > 0 {
		return allowed
	}
	return []string{loopbackIPv4, "::1"}
}

// ManagementListenerWorldOpen reports whether the dedicated management listener
// admits a connection from any address: bound to every interface, with an
// allowlist that constrains nothing. It is the condition the listener warns
// about at startup, exported so the security advisory reports the same one.
func ManagementListenerWorldOpen(cfg *gateonv1.ManagementConfig) bool {
	return isWildcardBind(ManagementBind(cfg)) && allowsEveryAddress(ManagementAllowedIPs(cfg))
}

func startSecureManagementServer(port string, deps *Deps, wg *syncutil.WaitGroup) {
	bind := ManagementBind(deps.ManagementConfig)
	mgmtPort := managementPort(port, deps.ManagementConfig)
	addr := net.JoinHostPort(bind, mgmtPort)

	// IP Whitelisting for management entrypoint
	allowedIPs := ManagementAllowedIPs(deps.ManagementConfig)

	warnIfManagementWorldOpen(bind, mgmtPort, allowedIPs)

	handler := middleware.Chain(
		middleware.EntryPoint("management", "management", true),
		middleware.Recovery(),
		middleware.SecurityHeaders(middleware.SecurityHeadersConfig{Preset: "recommended"}),
		middleware.HostFilter(managementHost(bind)),
		security.IPFilter(allowedIPs, nil),
		traffic.MaxConnections(500),
	)(deps.BaseHandler)

	server := newManagementHTTPServer(addr, handler)

	if deps.ShutdownRegistry != nil {
		deps.ShutdownRegistry.Register(func(ctx context.Context) error {
			return shutdownHTTPServer(ctx, server)
		})
	}

	logger.L.LogInfo("Secure Management Entrypoint started", "addr", addr)
	wg.Go(func() { serveManagement(server, addr, deps.Phantom) })
}

// managementPort is GATEON_MANAGEMENT_PORT, else the configured port, else the
// gateway's own port.
func managementPort(port string, cfg *gateonv1.ManagementConfig) string {
	if envPort := os.Getenv("GATEON_MANAGEMENT_PORT"); envPort != "" {
		return envPort
	}
	if p := cfg.GetPort(); p != "" {
		return p
	}
	return port
}

// managementHost is the Host the management listener answers to:
// GATEON_MANAGEMENT_HOST, else a named bind address, else any.
func managementHost(bind string) string {
	if envHost := os.Getenv("GATEON_MANAGEMENT_HOST"); envHost != "" {
		return envHost
	}
	if !isWildcardBind(bind) && net.ParseIP(bind) == nil {
		return bind
	}
	return ""
}

// serveManagement listens on addr and serves the management API until the
// server is shut down.
func serveManagement(server *http.Server, addr string, phantom PhantomCore) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logger.L.LogError("Management listen failed", "error", err)
		return
	}
	defer l.Close()

	if phantom != nil {
		l = phantom.OptimizeListener(l)
	}

	if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.L.LogError("Management server failed", "error", err)
	}
}

// newManagementHTTPServer builds the management listener's HTTP server.
func newManagementHTTPServer(addr string, handler http.Handler) *http.Server {
	// Enable H2C (HTTP/2 Cleartext) support for gRPC and modern HTTP clients.
	// In Go 1.26+, this is handled natively via the Protocols field.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	return &http.Server{
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
}

func startTCPServer(addr string, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup, shutdownReg *ShutdownRegistry) {
	logger.L.Info().Str("addr", addr).Str("ep", ep.Id).Msg("starting TCP entrypoint")
	var l net.Listener
	var err error
	// terminatesTLS decides both how to listen and whether to inspect. The
	// inspection decision used to key off deps.TLSConfig alone, which is the
	// gateway-wide config that any HTTPS entrypoint creates, so a plaintext TCP
	// entrypoint next to an HTTPS one silently lost SSH, RDP and HTTP detection.
	terminatesTLS := ep.Tls != nil && ep.Tls.Enabled && deps.TLSConfig != nil
	if terminatesTLS {
		l, err = tls.Listen("tcp", addr, deps.TLSConfig)
	} else {
		l, err = net.Listen("tcp", addr)
	}
	if err != nil {
		logger.L.LogError("TCP listen failed", "error", err, "addr", addr)
		return
	}
	s := &tcpServer{ep: ep, deps: deps, wg: wg, conns: newOpenConns(tcpConnLimit(ep)), plaintext: !terminatesTLS}
	if shutdownReg != nil {
		shutdownReg.Register(func(ctx context.Context) error {
			err := l.Close()
			s.conns.shutdown(ctx)
			return err
		})
	}
	wg.Go(func() { s.serve(l) })
}

// tcpServer is a TCP entrypoint's accept loop and the connections it holds.
type tcpServer struct {
	ep        *gateonv1.EntryPoint
	deps      *Deps
	wg        *syncutil.WaitGroup
	conns     *openConns
	plaintext bool
}

// tcpConnLimit is the most connections ep holds open at once: its
// max_connections, or the resource profile's default when that is 0. It was
// stored and shown and read by nothing, so a TCP entrypoint had no cap at all.
func tcpConnLimit(ep *gateonv1.EntryPoint) int {
	if n := int(ep.GetMaxConnections()); n > 0 {
		return n
	}
	return config.CurrentTierDefaults().TCPMaxConnections
}

// serve accepts until l is closed. A connection past the limit is closed at
// once, so the loop never waits for a slot.
func (s *tcpServer) serve(l net.Listener) {
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			telemetry.GlobalDiagnostics.RecordEPError(s.ep.Id, err.Error())
			return
		}
		switch s.conns.add(conn) {
		case refusedClosing:
			_ = conn.Close()
		case refusedFull:
			s.refuseOverLimit(conn)
		case admitted:
			telemetry.GlobalDiagnostics.RecordConnection(s.ep.Id)
			s.wg.Go(func() {
				defer s.conns.remove(conn)
				defer telemetry.GlobalDiagnostics.RecordDisconnect(s.ep.Id)
				s.handle(conn)
			})
		}
	}
}

// handle serves one admitted connection: inspected on a plaintext
// entrypoint, proxied to the entrypoint's route on one that terminates TLS.
func (s *tcpServer) handle(c net.Conn) {
	if s.plaintext {
		handleTCPConnWithInspection(c, s.ep, s.deps, s.wg)
		return
	}
	defer c.Close()
	if p := resolveTCPRoute(s.ep, s.deps, ""); p != nil {
		handleTCPProxyL4(c, p)
		return
	}
	handleTCPConn(c)
}

// refuseOverLimit closes a connection accepted while the entrypoint already
// holds its limit. Every refusal is counted with the other connection-limit
// rejections; the log says so at most once a minute, so that a flood of them
// is not also a flood of log lines.
func (s *tcpServer) refuseOverLimit(c net.Conn) {
	_ = c.Close()
	telemetry.IncInflightRejected("tcp_max_connections")
	if s.conns.warnDue(time.Now()) {
		logger.L.LogWarn("TCP entrypoint at its connection limit, refusing new connections",
			"ep", s.ep.Id, "max_connections", s.conns.limit)
	}
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

// How long a plaintext TCP entrypoint waits for a client's first bytes. A
// client of a client-first protocol -- HTTP, TLS, SSH, RDP, PostgreSQL, Redis
// -- sends them the moment it is connected, and they say where it goes. A
// client of a server-first protocol -- SMTP, POP3, IMAP, FTP, MySQL, VNC --
// sends nothing until the server has greeted it, so only silence identifies
// it, and only the backend can end the silence.
const (
	// serverFirstWait is how long a client may say nothing before it is taken
	// to be waiting for the server, and handed to the entrypoint's TCP route
	// so the backend can greet it. Every server-first session pays it before
	// its greeting, which is why it is short. A client that speaks first, but
	// later than this, goes to that route uninspected: harmless for TLS, which
	// a plaintext entrypoint sends there anyway, wrong for HTTP -- and for SSH
	// and RDP where they have routes of their own.
	//
	// Measured in network namespaces shaped with netem (curl, OpenSSL,
	// OpenSSH, Go's HTTP and TLS clients): opening bytes follow the
	// handshake's last ACK at once whatever the round-trip time, all read
	// within 11 ms of accept at 300 and 600 ms RTT. They come later behind a
	// slow uplink -- a full segment, Go's TLS ClientHello, 210 ms at 64
	// kbit/s; an HTTP request 25 ms -- or when their segment is lost and
	// resent: 280-310 ms later at 50 ms RTT, 610-660 ms at 200 ms. Half a
	// second covers a full segment down to ~25 kbit/s and one loss up to
	// ~150 ms RTT, and is half the second every silent client used to wait
	// before it was answered at all.
	serverFirstWait = 500 * time.Millisecond

	// silentLimit is how long a client of an entrypoint without a TCP route
	// -- nothing a silent client could be waiting for -- may say nothing
	// before it is told there is no route and closed. It is the second it
	// always had: such an entrypoint gains nothing from waiting less.
	silentLimit = time.Second
)

// noRouteReply is what a connection no route claims is told before it is
// closed. It used to be "Gateon TCP Entrypoint - " and the time, which said
// nothing about why the connection was ending -- and time.Time's String form
// ends in the process's monotonic clock reading, which is its uptime.
const noRouteReply = "Gateon TCP Entrypoint - no route for this connection\n"

func handleTCPConnWithInspection(conn net.Conn, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup) {
	if debugLogging() {
		logger.L.LogDebug("TCP connection received for inspection", "ep", ep.Id, "remote", conn.RemoteAddr().String())
	}
	// The peek buffer goes back to the pool when this returns, which for an L4
	// session is when the session ends: only a path that hands the bytes to
	// another goroutine copies them.
	peekPtr := peekPool.Get().(*[]byte)
	defer peekPool.Put(peekPtr)

	first, ok := awaitFirstBytes(conn, *peekPtr, ep, deps)
	if !ok {
		return
	}
	if len(first) > 0 && routeInspected(conn, first, ep, deps) {
		return
	}
	answerUnrouted(conn, first, ep)
}

// awaitFirstBytes returns the first bytes the client sends, to identify its
// protocol. A client silent for serverFirstWait is waiting for the server to
// speak first: if the entrypoint has a TCP route it is proxied there, and ok
// is false. Without one it may speak until silentLimit, and first is empty if
// it does not. ok is false too when the client went away first, and conn has
// been closed.
func awaitFirstBytes(conn net.Conn, peek []byte, ep *gateonv1.EntryPoint, deps *Deps) (first []byte, ok bool) {
	n, err := readWithin(conn, peek, serverFirstWait)
	if n == 0 && err == nil {
		if p := resolveTCPRoute(ep, deps, ""); p != nil {
			proxyServerFirst(conn, p, ep)
			return nil, false
		}
		n, err = readWithin(conn, peek, silentLimit-serverFirstWait)
	}
	if err != nil {
		// A client hanging up before it says anything -- a port scan, a TCP
		// health probe -- is routine. It was logged at ERROR, a line per
		// connection that buried the errors worth reading.
		if debugLogging() {
			logger.L.LogDebug("TCP inspection: client left before sending", "ep", ep.Id, "error", err)
		}
		_ = conn.Close()
		return nil, false
	}
	return peek[:n], true
}

// readWithin reads the client's first bytes into peek, waiting at most window.
// A client that sent nothing in time reads as n == 0 with a nil error, and
// conn is left with no deadline, ready for whoever serves it next.
func readWithin(conn net.Conn, peek []byte, window time.Duration) (int, error) {
	_ = conn.SetReadDeadline(time.Now().Add(window))
	n, err := conn.Read(peek)
	_ = conn.SetReadDeadline(time.Time{})
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return 0, nil
	}
	return n, err
}

// proxyServerFirst hands a client that has said nothing to the entrypoint's
// TCP route, so that the backend can greet it. The proxy gets the socket
// itself: nothing was read from it, so nothing needs replaying, and a
// *net.TCPConn is what the proxy can splice and half-close.
func proxyServerFirst(conn net.Conn, p l4.TCPProxy, ep *gateonv1.EntryPoint) {
	if debugLogging() {
		logger.L.LogDebug("TCP inspection: client silent, proxying so the backend can speak first",
			"ep", ep.Id, "waited", serverFirstWait, "remote", conn.RemoteAddr().String())
	}
	handleTCPProxyL4(conn, p)
}

// resolveTCPRoute returns the entrypoint's TCP route for protocol -- "" asks
// for its generic one -- or nil when there is none.
func resolveTCPRoute(ep *gateonv1.EntryPoint, deps *Deps, protocol string) l4.TCPProxy {
	if deps.L4Resolver == nil {
		return nil
	}
	return deps.L4Resolver.ResolveTCP(ep, protocol)
}

// routeInspected hands a connection whose first bytes are first to where they
// say it goes -- the entrypoint's HTTP server, or the L4 route for its
// protocol -- and reports whether anything took it.
func routeInspected(conn net.Conn, first []byte, ep *gateonv1.EntryPoint, deps *Deps) bool {
	if IsTCPAppHTTP(first) {
		if debugLogging() {
			logger.L.LogDebug("TCP inspection: HTTP detected", "ep", ep.Id)
		}
		// The shared HTTP server reads it on another goroutine, after the
		// peek buffer has gone back to the pool.
		serveConnAsHTTP(conn, bytes.Clone(first), ep, deps)
		return true
	}
	protocol := l4Protocol(first)
	p := resolveTCPRoute(ep, deps, protocol)
	if p == nil {
		return false
	}
	// One line per connection: DEBUG. At INFO it was two for SSH and RDP.
	if debugLogging() {
		logger.L.LogDebug("TCP inspection: route found, proxying",
			"ep", ep.Id, "protocol", protocol, "remote", conn.RemoteAddr().String())
	}
	handleTCPProxyL4(newPeekedConn(conn, first), p)
	return true
}

// l4Protocol names the protocol an L4 route can be chosen by: "ssh", "rdp",
// or "" for anything else.
func l4Protocol(first []byte) string {
	switch {
	case IsSSH(first):
		return "ssh"
	case IsRDP(first):
		return "rdp"
	default:
		return ""
	}
}

// answerUnrouted tells a connection nothing claimed that there is no route for
// it, and closes it: a client that sent a protocol the entrypoint has no route
// for, or one that said nothing on an entrypoint without a TCP route (bytes is
// 0). The DEBUG line used to call this a "fallback to generic TCP", which was
// never what happened.
func answerUnrouted(conn net.Conn, first []byte, ep *gateonv1.EntryPoint) {
	if debugLogging() {
		logger.L.LogDebug("TCP inspection: no route for this connection, closing it",
			"ep", ep.Id, "protocol", l4Protocol(first), "bytes", len(first), "remote", conn.RemoteAddr().String())
	}
	handleTCPConn(conn)
	_ = conn.Close()
}

// debugLogging reports whether DEBUG lines are written. The per-connection
// and per-packet ones ask first, so a disabled line formats nothing: its
// arguments -- a remote address rendered to a string, values boxed into the
// variadic slice -- cost allocations on every connection even when dropped.
func debugLogging() bool { return logger.L.IsEnabled(slog.LevelDebug) }

// handleTCPConn answers a connection no route claims with noRouteReply.
func handleTCPConn(conn net.Conn) {
	_, _ = io.WriteString(conn, noRouteReply)
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
		if debugLogging() {
			logger.L.Debug().Str("addr", addr.String()).Int("bytes", n).Msg("received UDP packet")
		}
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

// warnIfManagementWorldOpen logs a prominent warning when the management
// entrypoint is reachable from any address.
//
// The shipped default is bind 0.0.0.0 with an allowlist of 0.0.0.0/0 and ::/0,
// which is correct inside a container — a process bound to loopback there is
// unreachable through a published port, so tightening the default would break
// every Docker and Kubernetes deployment. It is the wrong posture on a host
// with a public address, where it puts the dashboard and the whole management
// API on the internet behind nothing but a login form.
//
// Since the safe value depends on how the operator deployed it, and neither
// choice is safe everywhere, this states the exposure plainly at startup rather
// than guessing. It is not a failure: an operator who meant it has already
// decided, and refusing to start would be worse than saying so.
func warnIfManagementWorldOpen(bind, port string, allowedIPs []string) {
	if !isWildcardBind(bind) {
		return
	}
	if !allowsEveryAddress(allowedIPs) {
		return
	}
	logger.L.LogWarn("management entrypoint is reachable from any address",
		"bind", bind,
		"port", port,
		"allowed_ips", strings.Join(allowedIPs, ","),
		"impact", "the dashboard and management API are exposed to every network this host is on",
		"action", "restrict management.allowed_ips to your admin network, or set GATEON_MANAGEMENT_ALLOWED_IPS",
		"note", "expected inside a container, where the container network is the boundary")
}

func isWildcardBind(bind string) bool {
	return bind == "" || bind == "0.0.0.0" || bind == "::" || bind == "[::]"
}

// allowsEveryAddress reports whether the allowlist covers the entire address
// space, i.e. constrains nothing.
func allowsEveryAddress(allowedIPs []string) bool {
	if len(allowedIPs) == 0 {
		return true
	}
	for _, cidr := range allowedIPs {
		switch strings.TrimSpace(cidr) {
		case "0.0.0.0/0", "::/0", "*":
			return true
		}
	}
	return false
}
