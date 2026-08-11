// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"cmp"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// peekedConn wraps a connection and returns buffered data first.
type peekedConn struct {
	net.Conn
	r io.Reader
}

func newPeekedConn(conn net.Conn, peeked []byte) *peekedConn {
	r := io.MultiReader(
		&bufFix{b: peeked},
		conn,
	)
	return &peekedConn{Conn: conn, r: r}
}

func (p *peekedConn) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

type bufFix struct {
	b []byte
	i int
}

func (b *bufFix) Read(p []byte) (int, error) {
	if b.i >= len(b.b) {
		return 0, io.EOF
	}
	n := copy(p, b.b[b.i:])
	b.i += n
	return n, nil
}

// sharedHTTPDispatcher implements net.Listener to feed connections into a shared http.Server.
type sharedHTTPDispatcher struct {
	conns chan net.Conn
	addr  net.Addr
}

func (d *sharedHTTPDispatcher) Accept() (net.Conn, error) {
	c, ok := <-d.conns
	if !ok {
		return nil, io.EOF
	}
	return c, nil
}

func (d *sharedHTTPDispatcher) Close() error {
	return nil // Server shutdown closes the dispatcher conceptually
}

func (d *sharedHTTPDispatcher) Addr() net.Addr {
	return d.addr
}

// buildPlainHTTPHandler builds the HTTP handler chain for an entrypoint (plaintext).
func buildPlainHTTPHandler(ep *gateonv1.EntryPoint, deps *Deps) http.Handler {
	var epHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isGRPC := (r.ProtoMajor == 2 || r.ProtoMajor == 3) && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
		isGRPCWeb := deps.Wrapped.IsGrpcWebRequest(r) || deps.Wrapped.IsAcceptableGrpcCorsRequest(r) || deps.Wrapped.IsGrpcWebSocketRequest(r)
		if isGRPC || isGRPCWeb {
			deps.Wrapped.ServeHTTP(w, r)
			return
		}
		deps.BaseHandler.ServeHTTP(w, r)
	})
	isMgmt := IsManagementAddress(ep.Address, deps)
	epLabel := cmp.Or(ep.Name, ep.Id)
	chain := []middleware.Middleware{
		middleware.EntryPoint(ep.Id, epLabel, isMgmt),
		middleware.Metrics("gateon-" + epLabel),
		middleware.IPMitigation(),
		middleware.UserMitigation(),
		middleware.Recovery(),
	}
	if ep.AccessLogEnabled {
		chain = append(chain, middleware.AccessLog("gateon-"+epLabel))
	}
	// CORS is handled at the route level for proxy traffic, and in BaseHandler for internal traffic.
	return middleware.Chain(chain...)(deps.Limiter.Handler(middleware.PerIP)(epHandler))
}

// serveConnAsHTTP serves a single connection as HTTP (plaintext) using a shared server.
// peeked contains the bytes already read during inspection; they are replayed first.
func serveConnAsHTTP(conn net.Conn, peeked []byte, ep *gateonv1.EntryPoint, deps *Deps) {
	val, ok := deps.SharedServers.Load(ep.Id)
	if !ok {
		d := &sharedHTTPDispatcher{
			conns: make(chan net.Conn, 4096),
			addr:  conn.LocalAddr(),
		}
		var loaded bool
		val, loaded = deps.SharedServers.LoadOrStore(ep.Id, d)
		if !loaded {
			// Start the shared server for this entrypoint
			go func() {
				handler := deps.TLSManager.HTTPChallengeHandler(buildPlainHTTPHandler(ep, deps))
				readTimeout, writeTimeout := resolveEPTimeouts(ep.Id, ep, deps)
				server := &http.Server{
					ReadHeaderTimeout: 10 * time.Second,
					ReadTimeout:       readTimeout,
					WriteTimeout:      writeTimeout,
					Handler:           handler,
					ErrorLog: logger.NewFilteredHandshakeLogger(logger.L, func(addr, err string) {
						telemetry.GlobalDiagnostics.RecordTLSError(ep.Id, addr, err)
					}),
				}
				if deps.ShutdownRegistry != nil {
					deps.ShutdownRegistry.Register(func(ctx context.Context) error {
						return server.Shutdown(ctx)
					})
				}
				if err := server.Serve(d); err != nil && err != http.ErrServerClosed {
					logger.L.LogError("shared http server failed", "ep", ep.Id, "error", err)
				}
			}()
		}
	}

	d := val.(*sharedHTTPDispatcher)
	select {
	case d.conns <- newPeekedConn(conn, peeked):
	default:
		// Connection queue full, drop to protect system
		logger.L.LogWarn("shared http connection queue full, dropping", "ep", ep.Id)
		_ = conn.Close()
	}
}
