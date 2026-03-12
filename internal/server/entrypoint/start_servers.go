package entrypoint

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gateon/gateon/internal/config"
	"github.com/gateon/gateon/internal/logger"
	"github.com/gateon/gateon/internal/middleware"
	"github.com/gateon/gateon/internal/syncutil"
	gtls "github.com/gateon/gateon/internal/tls"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/rs/cors"
)

// StartServers starts all entrypoints (HTTP, TCP, UDP) in goroutines.
// shutdownReg is used for graceful shutdown; pass nil to skip registering shutdown.
func StartServers(
	epReg *config.EntryPointRegistry,
	port string,
	baseHandler http.Handler,
	wrapped *grpcweb.WrappedGrpcServer,
	tlsConfig *tls.Config,
	tlsManager *gtls.Manager,
	c *cors.Cors,
	wg *syncutil.WaitGroup,
	shutdownReg *ShutdownRegistry,
) {
	limiter := middleware.NewQPSRateLimiter(10, 20)
	entryPoints := epReg.List()
	if len(entryPoints) == 0 {
		entryPoints = append(entryPoints, &gateonv1.EntryPoint{
			Id: "default", Name: "Default", Address: ":" + port, Type: gateonv1.EntryPoint_HTTP,
		})
	}
	deps := &Deps{
		Port:             port,
		BaseHandler:      baseHandler,
		Wrapped:          wrapped,
		CORS:             c,
		TLSConfig:        tlsConfig,
		TLSManager:       tlsManager,
		Limiter:          limiter,
		ShutdownRegistry: shutdownReg,
	}
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

func startTCPServer(addr string, tlsConfig *tls.Config, wg *syncutil.WaitGroup, shutdownReg *ShutdownRegistry) {
	logger.L.Info().Str("addr", addr).Msg("starting TCP entrypoint")
	var l net.Listener
	var err error
	if tlsConfig != nil {
		l, err = tls.Listen("tcp", addr, tlsConfig)
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
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer conn.Close()
				handleTCPConn(conn)
			})
		}
	})
}

func startUDPServer(addr string, wg *syncutil.WaitGroup, shutdownReg *ShutdownRegistry) {
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
	wg.Go(func() {
		defer conn.Close()
		handleUDPConn(conn)
	})
}

func handleTCPConn(conn net.Conn) {
	fmt.Fprintf(conn, "Gateon TCP Entrypoint - %s\n", time.Now().String())
}

func handleUDPConn(conn *net.UDPConn) {
	buf := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		logger.L.Debug().Str("addr", addr.String()).Int("bytes", n).Msg("received UDP packet")
	}
}
