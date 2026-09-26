// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/syncutil"
	gtls "github.com/gsoultan/gateon/internal/tls"
	"github.com/gsoultan/gateon/pkg/l4"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// GRPCWebHandler handles gRPC-Web requests (e.g. *grpcweb.WrappedGrpcServer).
type GRPCWebHandler interface {
	IsGrpcWebRequest(r *http.Request) bool
	IsAcceptableGrpcCorsRequest(r *http.Request) bool
	IsGrpcWebSocketRequest(r *http.Request) bool
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// Runner is the strategy interface for starting one kind of entrypoint.
type Runner interface {
	Run(ctx context.Context, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup)
}

// ShutdownRegistry collects shutdown functions for graceful exit.
type ShutdownRegistry struct {
	mu    sync.Mutex
	funcs []func(context.Context) error
}

// Register adds a shutdown function (e.g. server.Shutdown).
func (r *ShutdownRegistry) Register(fn func(context.Context) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.funcs = append(r.funcs, fn)
}

// shutdownHTTPServer drains srv until ctx expires and then closes whatever is
// still open.
//
// Shutdown on its own is not a bounded operation: it waits for every active
// connection to go idle, so one request that never ends by itself -- an SSE
// stream, a stuck upload, a proxied backend that never answers -- holds it
// open forever unless the context says otherwise. Close is what ends those
// requests: closing the connection cancels the handler's context.
func shutdownHTTPServer(ctx context.Context, srv *http.Server) error {
	err := srv.Shutdown(ctx)
	if err != nil {
		_ = srv.Close()
	}
	return err
}

// openConns tracks the connections a TCP entrypoint has accepted, so its
// shutdown can let them finish and then close whatever is still open when the
// deadline passes.
//
// An L4 session has no request boundary to drain at: an idle SSH or database
// session lasts exactly as long as its client keeps it. Closing the listener
// alone left every such session -- and the goroutine serving it, which Run
// waits for -- running until the process was killed.
type openConns struct {
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	closing  bool
	drained  chan struct{}
	signaled bool
}

func newOpenConns() *openConns {
	return &openConns{conns: make(map[net.Conn]struct{}), drained: make(chan struct{})}
}

// add records c. It reports false once shutdown has begun, in which case the
// caller closes c instead of serving it.
func (o *openConns) add(c net.Conn) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closing {
		return false
	}
	o.conns[c] = struct{}{}
	return true
}

// remove forgets c once the goroutine serving it is done with it.
func (o *openConns) remove(c net.Conn) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.conns, c)
	if o.closing && len(o.conns) == 0 {
		o.signalDrainedLocked()
	}
}

func (o *openConns) signalDrainedLocked() {
	if !o.signaled {
		o.signaled = true
		close(o.drained)
	}
}

// shutdown refuses new connections, waits for the open ones to finish until
// ctx is done, and then closes the rest.
func (o *openConns) shutdown(ctx context.Context) {
	o.mu.Lock()
	o.closing = true
	if len(o.conns) == 0 {
		o.signalDrainedLocked()
	}
	o.mu.Unlock()

	select {
	case <-o.drained:
		return
	case <-ctx.Done():
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for c := range o.conns {
		_ = c.Close()
	}
}

// ShutdownAll runs every registered shutdown function against ctx at the same
// time, and returns once all of them have.
//
// At the same time, because ctx carries one deadline for the whole process.
// Called in turn, a server with a request that never finishes by itself -- the
// management listener with a dashboard tab open is enough -- spent that entire
// deadline draining, while every server registered after it kept its listener
// open and accepting for the whole window and was then handed an expired
// context: closed with no drain at all.
func (r *ShutdownRegistry) ShutdownAll(ctx context.Context) {
	r.mu.Lock()
	list := make([]func(context.Context) error, len(r.funcs))
	copy(list, r.funcs)
	r.mu.Unlock()
	var wg sync.WaitGroup
	for _, fn := range list {
		wg.Go(func() {
			if err := fn(ctx); err != nil {
				logger.L.LogDebug("shutdown callback error", "error", err)
			}
		})
	}
	wg.Wait()
}

// L4Resolver resolves L4 backends from Route -> Service. Nil for HTTP-only setups.
// Returns interfaces so consumers depend on abstractions (DIP).
type L4Resolver interface {
	ResolveTCP(ep *gateonv1.EntryPoint, protocol string) l4.TCPProxy
	ResolveUDP(ep *gateonv1.EntryPoint) l4.UDPProxy
}

// PhantomCore defines the interface for the high-performance TITAN proxy core.
type PhantomCore interface {
	ProxyL4(ctx context.Context, client net.Conn, targetAddr string) error
	OptimizeListener(l net.Listener) net.Listener
}

// WrapL4Resolver adapts *l4.Resolver to L4Resolver (concrete returns -> interface returns).
func WrapL4Resolver(r *l4.Resolver) L4Resolver {
	if r == nil {
		return nil
	}
	return &l4ResolverAdapter{r: r}
}

type l4ResolverAdapter struct{ r *l4.Resolver }

func (a *l4ResolverAdapter) ResolveTCP(ep *gateonv1.EntryPoint, protocol string) l4.TCPProxy {
	p := a.r.ResolveTCP(ep, protocol)
	if p == nil {
		return nil
	}
	return p
}

func (a *l4ResolverAdapter) ResolveUDP(ep *gateonv1.EntryPoint) l4.UDPProxy {
	p := a.r.ResolveUDP(ep)
	if p == nil {
		return nil
	}
	return p
}

// Deps holds dependencies needed to run entrypoints.
type Deps struct {
	Port             string
	EpStore          config.EntryPointStore
	BaseHandler      http.Handler
	Wrapped          GRPCWebHandler
	TLSConfig        *tls.Config
	TLSManager       gtls.TLSManager
	Limiter          RateLimiter
	ShutdownRegistry *ShutdownRegistry
	L4Resolver       L4Resolver
	ManagementConfig *gateonv1.ManagementConfig
	GlobalStore      config.GlobalConfigStore
	SharedServers    sync.Map // map[string]*sharedHTTPDispatcher
	Phantom          PhantomCore
}

// RateLimiter provides per-key rate limiting middleware.
type RateLimiter interface {
	Handler(keyFunc func(*http.Request) string) func(http.Handler) http.Handler
}

func runnerFor(epType gateonv1.EntryPoint_Type) Runner {
	switch epType {
	case gateonv1.EntryPoint_HTTP, gateonv1.EntryPoint_HTTP2, gateonv1.EntryPoint_GRPC, gateonv1.EntryPoint_HTTP3:
		return &httpRunner{}
	case gateonv1.EntryPoint_TCP:
		return &tcpRunner{}
	case gateonv1.EntryPoint_UDP:
		return &udpRunner{}
	default:
		return nil
	}
}
