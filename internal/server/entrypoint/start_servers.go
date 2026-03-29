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
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/syncutil"
	gtls "github.com/gsoultan/gateon/internal/tls"
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
	corsProvider CORSProvider,
	wg *syncutil.WaitGroup,
	shutdownReg *ShutdownRegistry,
	l4Resolver L4Resolver,
) {
	limiter := entrypointRateLimiter()
	deps := &Deps{
		Port:             port,
		BaseHandler:      baseHandler,
		Wrapped:          wrapped,
		CORS:             corsProvider,
		TLSConfig:        tlsConfig,
		TLSManager:       tlsManager,
		Limiter:          limiter,
		ShutdownRegistry: shutdownReg,
		L4Resolver:       l4Resolver,
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
	bind := os.Getenv("GATEON_MANAGEMENT_BIND")
	if bind == "" {
		bind = "127.0.0.1"
	}
	addr := bind + ":" + port

	// IP Whitelisting for management entrypoint
	allowedIPsStr := os.Getenv("GATEON_MANAGEMENT_ALLOWED_IPS")
	allowedIPs := []string{"127.0.0.1", "::1"}
	if allowedIPsStr != "" {
		allowedIPs = strings.Split(allowedIPsStr, ",")
	}

	handler := middleware.Chain(
		middleware.Recovery(),
		middleware.IPFilter(allowedIPs, nil),
		middleware.MaxConnections(500),
	)(injectEntryPointID("management", deps.BaseHandler))

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if deps.ShutdownRegistry != nil {
		deps.ShutdownRegistry.Register(server.Shutdown)
	}

	logger.L.Info().Str("addr", addr).Msg("Secure Management Entrypoint started")
	wg.Go(func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.L.Error().Err(err).Msg("Management server failed")
		}
	})
}

func startTCPServer(addr string, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup, shutdownReg *ShutdownRegistry) {
	logger.L.Info().Str("addr", addr).Str("ep", ep.Id).Msg("starting TCP entrypoint")
	var l net.Listener
	var err error
	if deps.TLSConfig != nil {
		l, err = tls.Listen("tcp", addr, deps.TLSConfig)
	} else {
		l, err = net.Listen("tcp", addr)
	}
	if err != nil {
		logger.L.Error().Err(err).Str("addr", addr).Msg("TCP listen failed")
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
				return
			}
			c := conn
			if plaintext {
				wg.Go(func() {
					handleTCPConnWithInspection(c, ep, deps, wg)
				})
			} else {
				var p TCPProxy
				if deps.L4Resolver != nil {
					p = deps.L4Resolver.ResolveTCP(ep)
				}
				wg.Go(func() {
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
	logger.L.Info().Str("addr", addr).Msg("starting UDP entrypoint")
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logger.L.Error().Err(err).Str("addr", addr).Msg("UDP resolve failed")
		return
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		logger.L.Error().Err(err).Str("addr", addr).Msg("UDP listen failed")
		return
	}
	if shutdownReg != nil {
		shutdownReg.Register(func(context.Context) error {
			return conn.Close()
		})
	}
	var proxy UDPProxy
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

const peekTimeout = 200 * time.Millisecond

func handleTCPConnWithInspection(conn net.Conn, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(peekTimeout))
	peek := make([]byte, PeekSize)
	n, err := io.ReadFull(conn, peek)
	conn.SetReadDeadline(time.Time{})
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		conn.Close()
		return
	}
	peeked := peek[:n]
	if n > 0 && IsTCPAppHTTP(peeked) {
		serveConnAsHTTP(conn, peeked, ep, deps)
		return
	}
	var p TCPProxy
	if deps.L4Resolver != nil {
		p = deps.L4Resolver.ResolveTCP(ep)
	}
	if p != nil {
		connWithPeek := newPeekedConn(conn, peeked)
		handleTCPProxyL4(connWithPeek, p)
	} else {
		connWithPeek := newPeekedConn(conn, peeked)
		handleTCPConn(connWithPeek)
	}
}

func handleTCPConn(conn net.Conn) {
	_, _ = fmt.Fprintf(conn, "Gateon TCP Entrypoint - %s\n", time.Now().String())
}

func handleTCPProxyL4(client net.Conn, pool TCPProxy) {
	pool.ProxyTCP(context.Background(), client)
}

func copyAndClose(dst net.Conn, src net.Conn) (int64, error) {
	defer dst.Close()
	return io.Copy(dst, src)
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

func handleUDPProxyL4(conn *net.UDPConn, proxy UDPProxy) {
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
