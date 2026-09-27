// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"net"
	"net/http"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/middleware/traffic"
	"github.com/gsoultan/gateon/pkg/l4"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The L4 proxy finds the socket beneath an inspected connection through this
// interface; renaming either side must break the build, not silently put every
// plaintext L4 session back on a user-space copy.
var _ l4.ReadAheadConn = (*peekedConn)(nil)

// peekedConn is a connection whose first bytes were read to identify its
// protocol. Read returns those bytes first, then the connection's own.
type peekedConn struct {
	net.Conn
	peeked []byte // read during inspection and not yet returned by Read
}

func newPeekedConn(conn net.Conn, peeked []byte) *peekedConn {
	return &peekedConn{Conn: conn, peeked: peeked}
}

func (p *peekedConn) Read(b []byte) (int, error) {
	if len(p.peeked) > 0 {
		n := copy(b, p.peeked)
		p.peeked = p.peeked[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// ReadAhead implements l4.ReadAheadConn: the L4 proxy sends the unread bytes
// itself and then moves the rest between the sockets directly -- by splice(2)
// on Linux, which it cannot do through this wrapper's type -- and half-closes
// the client when the backend is done, which it cannot do either, since the
// wrapper has no CloseWrite.
func (p *peekedConn) ReadAhead() ([]byte, net.Conn) {
	pending := p.peeked
	p.peeked = nil
	return pending, p.Conn
}

// sharedHTTPDispatcher implements net.Listener to feed connections into a shared http.Server.
type sharedHTTPDispatcher struct {
	conns     chan net.Conn
	addr      net.Addr
	done      chan struct{}
	closeOnce sync.Once
}

func newSharedHTTPDispatcher(addr net.Addr) *sharedHTTPDispatcher {
	return &sharedHTTPDispatcher{
		conns: make(chan net.Conn, 4096),
		addr:  addr,
		done:  make(chan struct{}),
	}
}

func (d *sharedHTTPDispatcher) Accept() (net.Conn, error) {
	// A closed dispatcher wins over a queued connection, so Serve stops
	// promptly instead of draining the queue first.
	select {
	case <-d.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case c := <-d.conns:
		return c, nil
	case <-d.done:
		return nil, net.ErrClosed
	}
}

// Close unblocks Accept. It has to: http.Server.Shutdown closes its listeners
// and then waits -- without consulting its context -- for every Serve loop to
// return, and Serve returns only when Accept does. This used to return nil and
// do nothing, so the first HTTP request a plaintext TCP entrypoint inspected
// left the process unable to finish a graceful shutdown at all.
func (d *sharedHTTPDispatcher) Close() error {
	d.closeOnce.Do(func() { close(d.done) })
	return nil
}

func (d *sharedHTTPDispatcher) Addr() net.Addr {
	return d.addr
}

// buildPlainHTTPHandler builds the HTTP handler chain for an entrypoint (plaintext).
func buildPlainHTTPHandler(ep *gateonv1.EntryPoint, deps *Deps) http.Handler {
	// Every request, gRPC included, goes to the base handler: it proxies a
	// request a route matches -- gRPC routes too -- and it is where a data-plane
	// entrypoint refuses the management API and where that API authenticates.
	// gRPC and gRPC-Web used to be handed straight to the internal gRPC server
	// ahead of it, and that server's permission check read "no caller" as "auth
	// disabled": anyone who could reach this port could call the management
	// API, UpdateGlobalConfig included, with no credential. ADR 0027.
	epHandler := deps.BaseHandler
	// The HTTP entrypoint's chain, not a copy of it. The copy this used to be
	// had fallen behind: no global honeypot, no global GeoIP country block and
	// no per-IP connection limit, so plain HTTP to a TCP entrypoint skipped all
	// three. The shared server lives as long as the process, hence Background.
	chain := entrypointChain(context.Background(), ep, deps)
	return middleware.Chain(chain...)(deps.Limiter.Handler(traffic.PerIP)(epHandler))
}

// serveConnAsHTTP serves a single connection as HTTP (plaintext) using a shared server.
// peeked contains the bytes already read during inspection; they are replayed first.
func serveConnAsHTTP(conn net.Conn, peeked []byte, ep *gateonv1.EntryPoint, deps *Deps) {
	val, ok := deps.SharedServers.Load(ep.Id)
	if !ok {
		d := newSharedHTTPDispatcher(conn.LocalAddr())
		var loaded bool
		val, loaded = deps.SharedServers.LoadOrStore(ep.Id, d)
		if !loaded {
			// Start the shared server for this entrypoint
			go func() {
				// The HTTP entrypoint's server and its per-request deadlines,
				// not a server of its own. This one set the entrypoint's
				// timeouts on the server, where a write timeout bounds the
				// whole response and survives a hijack -- so an event stream
				// or a WebSocket through a TCP entrypoint was cut after
				// fifteen seconds -- and it did not speak cleartext HTTP/2,
				// so the gRPC branch of the handler below could not be
				// reached. newServer also bounds HTTP/2 streams, which a
				// server of its own would have had to repeat.
				handler := dynamicTimeouts(ep, deps,
					deps.TLSManager.HTTPChallengeHandler(buildPlainHTTPHandler(ep, deps)))
				server := (&httpEntrypoint{ep: ep, deps: deps}).newServer(handler)
				if deps.ShutdownRegistry != nil {
					deps.ShutdownRegistry.Register(func(ctx context.Context) error {
						return shutdownHTTPServer(ctx, server)
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
	case <-d.done:
		// Shut down: nothing will ever accept from the queue again.
		_ = conn.Close()
		return
	default:
	}
	select {
	case d.conns <- newPeekedConn(conn, peeked):
	default:
		// Connection queue full, drop to protect system
		logger.L.LogWarn("shared http connection queue full, dropping", "ep", ep.Id)
		_ = conn.Close()
	}
}
