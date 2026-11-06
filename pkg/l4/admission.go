// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The ipfilter middlewares a TCP route lists, enforced on its connections.
//
// A route's middlewares used to be read only by the HTTP router. The dashboard
// offered the same policy picker on a TCP route, and saved what was picked, so
// an SSH route with an ipfilter attached looked restricted and accepted every
// address: nothing on the L4 path ever read the list. That matters most for
// exactly the traffic it is attached to -- an SSH or RDP backend reachable from
// anywhere is the exposure CVE-2026-123158 (OpenSSH password bypass) turns into
// a root shell, and a gateway cannot see inside the encrypted session to help.
// Who may open the connection at all is the one thing it can decide.

// AddrFilterBuilder turns an ipfilter middleware's stored config into a
// decision about a connection's peer address: true admits it.
type AddrFilterBuilder func(cfg map[string]string) (func(netip.Addr) bool, error)

const ipFilterType = "ipfilter"

// SetAddrFilters makes every TCP route enforce the ipfilter middlewares it
// lists, read from store and built by build. Call it once, before the
// resolver serves a connection. Without it the resolver enforces none, which
// is what tests that build a bare resolver get.
func (r *Resolver) SetAddrFilters(store config.MiddlewareStore, build AddrFilterBuilder) {
	r.mwStore, r.buildFilter = store, build
}

// cachedGuard is the proxy a route's connections are handed: its pool behind
// the route's filters. hash identifies the middlewares it was built from, and
// pool the pool it wraps, so either changing rebuilds it.
type cachedGuard struct {
	hash  uint64
	pool  *TCPBackendPool
	proxy TCPProxy
}

// admit returns pool behind the address filters rt lists, built once per
// change to those middlewares rather than per connection.
func (r *Resolver) admit(key tcpPoolKey, rt *gateonv1.Route, pool *TCPBackendPool) TCPProxy {
	if r.mwStore == nil || r.buildFilter == nil || len(rt.Middlewares) == 0 {
		return pool
	}
	hash := r.middlewaresHash(rt)
	r.mu.RLock()
	c, ok := r.guards[key]
	r.mu.RUnlock()
	if ok && c.hash == hash && c.pool == pool {
		return c.proxy
	}
	proxy := r.buildGuard(rt, pool)
	r.mu.Lock()
	r.guards[key] = &cachedGuard{hash: hash, pool: pool, proxy: proxy}
	r.mu.Unlock()
	return proxy
}

// middlewaresHash identifies what rt's middlewares are now: IDs in order, and
// for each one found its type and every config entry. It runs per connection,
// so it allocates nothing: config entries are combined order-independently
// rather than sorted, because map order is random.
func (r *Resolver) middlewaresHash(rt *gateonv1.Route) uint64 {
	ctx := context.Background()
	h := fnv64a(fnvOffset64)
	for _, id := range rt.Middlewares {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		h.field(id)
		mw, ok := r.mwStore.Get(ctx, id)
		if !ok || mw == nil {
			h.field("\x00missing")
			continue
		}
		h.field(mw.Type)
		var entries uint64
		for k, v := range mw.Config {
			e := fnv64a(fnvOffset64)
			e.field(k)
			e.field(v)
			entries ^= uint64(e)
		}
		var digits [20]byte
		h.fieldBytes(strconv.AppendUint(digits[:0], entries, 16))
	}
	return uint64(h)
}

// buildGuard builds the filters rt's middlewares name. A middleware that is
// missing, or an ipfilter that does not build, refuses every connection: the
// operator asked for a restriction, and serving without it is the open route
// the HTTP router also refuses to serve (route_problems.go). Middlewares of
// other types do nothing on a TCP connection, as they never did, and are
// logged when the guard is built so that is visible.
func (r *Resolver) buildGuard(rt *gateonv1.Route, pool *TCPBackendPool) TCPProxy {
	label := routeLabel(rt)
	var filters []func(netip.Addr) bool
	for _, id := range rt.Middlewares {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		mw, ok := r.mwStore.Get(context.Background(), id)
		if !ok || mw == nil {
			logger.L.LogWarn("L4 route names a middleware that does not exist; refusing its connections",
				"route", label, "middleware", id)
			return refusingTCP{}
		}
		if !strings.EqualFold(strings.TrimSpace(mw.Type), ipFilterType) {
			logger.L.LogWarn("L4 route lists a middleware that is not applied to TCP connections; only ipfilter is",
				"route", label, "middleware", id, "type", mw.Type)
			continue
		}
		f, err := r.buildFilter(mw.Config)
		if err != nil {
			logger.L.LogWarn("L4 route's ipfilter does not build; refusing its connections",
				"route", label, "middleware", id, "error", err)
			return refusingTCP{}
		}
		filters = append(filters, f)
	}
	if len(filters) == 0 {
		return pool
	}
	return &guardedTCP{filters: filters, next: pool, route: label}
}

func routeLabel(rt *gateonv1.Route) string {
	if rt.Name != "" {
		return rt.Name
	}
	return rt.Id
}

// guardedTCP admits a connection only when every filter admits its peer.
type guardedTCP struct {
	filters []func(netip.Addr) bool
	next    TCPProxy
	route   string
}

// ProxyTCP closes a connection whose peer any filter refuses, or whose peer
// cannot be read, before a backend is dialled.
func (g *guardedTCP) ProxyTCP(ctx context.Context, client net.Conn) {
	addr, ok := peerAddr(client)
	if !ok || !g.admits(addr) {
		// The address is passed as the net.Addr it is, so a disabled DEBUG
		// level formats nothing for a refused connection.
		logger.L.LogAttrs(ctx, slog.LevelDebug, "L4 connection refused by the route's ipfilter",
			slog.String("route", g.route), slog.Any("remote", client.RemoteAddr()))
		_ = client.Close()
		return
	}
	g.next.ProxyTCP(ctx, client)
}

func (g *guardedTCP) admits(addr netip.Addr) bool {
	for _, f := range g.filters {
		if !f(addr) {
			return false
		}
	}
	return true
}

// peerAddr is the TCP peer's address. It is never taken from anything the
// client sends: on an L4 connection there is nothing else to believe.
func peerAddr(c net.Conn) (netip.Addr, bool) {
	ra := c.RemoteAddr()
	if ta, ok := ra.(*net.TCPAddr); ok {
		addr := ta.AddrPort().Addr()
		return addr, addr.IsValid()
	}
	if ra == nil {
		return netip.Addr{}, false
	}
	ap, err := netip.ParseAddrPort(ra.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr(), true
}

// refusingTCP closes every connection: the route asked for a filter it does
// not have.
type refusingTCP struct{}

func (refusingTCP) ProxyTCP(_ context.Context, client net.Conn) { _ = client.Close() }
