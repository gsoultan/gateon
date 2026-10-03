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
	"github.com/gsoultan/gateon/internal/deadline"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/syncutil"
	"github.com/gsoultan/gateon/internal/telemetry"
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
// deadline passes, and so it can refuse connections past its limit.
//
// An L4 session has no request boundary to drain at: an idle SSH or database
// session lasts exactly as long as its client keeps it. Closing the listener
// alone left every such session -- and the goroutine serving it, which Run
// waits for -- running until the process was killed.
type openConns struct {
	mu sync.Mutex
	// conns maps each held connection to the source address it was admitted
	// under -- the IP, without its port. The address is kept so a block event
	// can close an address's sessions (closeByAddr) and so a per-address slot
	// is released under the same address it was taken. It is "" when the
	// per-address cap is off, in which case closeByAddr reads the address from
	// the connection instead.
	conns    map[net.Conn]string
	limit    int // most connections held at once; the map never grows past it
	perAddr  *perAddrLimiter
	closing  bool
	drained  chan struct{}
	signaled bool
	warn     limitWarning // when it last said it was at its limit
}

func newOpenConns(limit int, perAddr *perAddrLimiter) *openConns {
	return &openConns{conns: make(map[net.Conn]string), limit: limit, perAddr: perAddr, drained: make(chan struct{})}
}

// admission is what add decided about a connection.
type admission int

const (
	admitted       admission = iota
	refusedClosing           // shutdown has begun
	refusedFull              // limit connections are already open
	refusedPerAddr           // the source address holds its per-address limit
)

// add records c, unless shutdown has begun, limit connections are open already,
// or its source address already holds its per-address limit; the caller closes
// a connection that was not admitted instead of serving it. The per-address
// slot is taken here, under the same lock, so a connection counted in cannot
// slip past the cap between the check and being served.
func (o *openConns) add(c net.Conn) admission {
	o.mu.Lock()
	defer o.mu.Unlock()
	switch {
	case o.closing:
		return refusedClosing
	case len(o.conns) >= o.limit:
		return refusedFull
	}
	ip := ""
	if o.perAddr != nil {
		ip = peerIP(c)
		if !o.perAddr.acquire(ip) {
			return refusedPerAddr
		}
	}
	o.conns[c] = ip
	return admitted
}

// remove forgets c once the goroutine serving it is done with it, and returns
// its per-address slot under the address it was admitted with.
func (o *openConns) remove(c net.Conn) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.perAddr != nil {
		o.perAddr.release(o.conns[c])
	}
	delete(o.conns, c)
	if o.closing && len(o.conns) == 0 {
		o.signalDrainedLocked()
	}
}

// closeByAddr closes every held connection whose source address is ip and
// returns how many it closed. It is driven by a block event, never the request
// path, and one entrypoint's scan is bounded by its connection cap. Closing the
// socket is what ends the session: the goroutine serving it unblocks, its
// handler returns, and remove forgets it -- this does not wait for that, so it
// cannot deadlock against remove taking the same lock.
func (o *openConns) closeByAddr(ip string) int {
	if ip == "" {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for c, addr := range o.conns {
		if addr == "" {
			addr = peerIP(c)
		}
		if addr == ip {
			_ = c.Close()
			n++
		}
	}
	return n
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

// blockedSessions is every running TCP entrypoint's open-connection set, so a
// block event can reach the sessions each holds. An entrypoint registers when
// it starts serving and deregisters when it shuts down, so the set is exactly
// the entrypoints alive now -- a hot-reload that replaces an entrypoint does
// not leak the old one. A block iterates it: the number of TCP entrypoints,
// each scan bounded by that entrypoint's connection cap (ADR 0036).
var blockedSessions = &openConnsRegistry{sets: make(map[*openConns]struct{})}

type openConnsRegistry struct {
	mu   sync.Mutex
	sets map[*openConns]struct{}
}

func (r *openConnsRegistry) add(o *openConns) {
	r.mu.Lock()
	r.sets[o] = struct{}{}
	r.mu.Unlock()
}

func (r *openConnsRegistry) remove(o *openConns) {
	r.mu.Lock()
	delete(r.sets, o)
	r.mu.Unlock()
}

// closeBlocked closes the open connections of ip across every registered
// entrypoint and returns how many it closed. The registry lock is held only
// long enough to copy the sets out, so a slow close cannot hold up a concurrent
// register or deregister.
func (r *openConnsRegistry) closeBlocked(ip string) int {
	r.mu.Lock()
	sets := make([]*openConns, 0, len(r.sets))
	for o := range r.sets {
		sets = append(sets, o)
	}
	r.mu.Unlock()
	n := 0
	for _, o := range sets {
		n += o.closeByAddr(ip)
	}
	return n
}

// onIPBlocked is the block-event hook the telemetry layer fires when an address
// is added to the IP mitigation list. It closes that address's open L4 sessions
// on every TCP entrypoint -- unless the address is exempt from enforcement
// (loopback or the allowlist) or has since been released, which
// identity.AddressBlocked reports together: an allowlisted address an operator
// also blocked is never cut, matching the accept-time check.
func onIPBlocked(ip string) {
	if !identity.AddressBlocked(ip) {
		return
	}
	if n := blockedSessions.closeBlocked(ip); n > 0 {
		logger.L.LogInfo("closed open sessions of a newly blocked address", "ip", ip, "sessions", n)
	}
}

func init() { telemetry.RegisterIPBlockHook(onIPBlocked) }

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

// PhantomCore is what the entrypoints ask of the phantom core: the listener to
// serve on. L4 sessions go to the route's l4.TCPProxy after inspection.
type PhantomCore interface {
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

// OnlyTCPRoute reports ep's tcp route when it is all ep serves; see
// l4.Resolver.OnlyTCPRoute.
func (a *l4ResolverAdapter) OnlyTCPRoute(ep *gateonv1.EntryPoint) l4.TCPProxy {
	if p := a.r.OnlyTCPRoute(ep); p != nil {
		return p
	}
	return nil
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
	// ManagementTimeouts are the management listener's per-request bounds;
	// nil is defaultManagementTimeouts, which is what production runs.
	ManagementTimeouts *deadline.RequestTimeouts
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
