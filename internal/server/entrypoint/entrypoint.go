// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

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

// ShutdownAll runs all registered shutdown functions with the given context.
func (r *ShutdownRegistry) ShutdownAll(ctx context.Context) {
	r.mu.Lock()
	list := make([]func(context.Context) error, len(r.funcs))
	copy(list, r.funcs)
	r.mu.Unlock()
	for _, fn := range list {
		if err := fn(ctx); err != nil {
			logger.L.LogDebug("shutdown callback error", "error", err)
		}
	}
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
