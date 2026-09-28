// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"context"
	"strings"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// routeClaims records, for the routes a route store held at one moment, the
// entrypoints on which something other than a tcp route can claim a
// connection -- an HTTP, gRPC, ssh or rdp route -- so that its first bytes
// must be read to tell which. It is built once per set of routes and read by
// every connection, so reading it costs a map lookup; its maps are keyed by
// configured entrypoint IDs, never by anything a client sends.
type routeClaims struct {
	routes     []*gateonv1.Route // the slice it was built from
	everywhere bool              // an HTTP-served route lists no entrypoint, so it is served on all
	inspected  map[string]struct{}
}

func newRouteClaims(routes []*gateonv1.Route) *routeClaims {
	c := &routeClaims{routes: routes, inspected: make(map[string]struct{})}
	for _, rt := range routes {
		if rt.Disabled {
			continue
		}
		switch strings.ToLower(rt.Type) {
		case "tcp", "udp":
			// Not told apart by the first bytes: tcp is what is left over,
			// and udp is another listener.
		case "ssh", "rdp":
			// Served only where listed, and only with a service, as
			// SelectL4Route chooses them.
			if rt.ServiceId != "" {
				c.add(rt.Entrypoints)
			}
		default:
			// HTTP, gRPC, GraphQL: the router serves a route that lists no
			// entrypoint on every one.
			if len(rt.Entrypoints) == 0 {
				c.everywhere = true
			}
			c.add(rt.Entrypoints)
		}
	}
	return c
}

func (c *routeClaims) add(entrypoints []string) {
	for _, e := range entrypoints {
		c.inspected[e] = struct{}{}
	}
}

// inspects reports whether a connection on entrypoint epID can be claimed by
// something that only its first bytes tell apart from a tcp route.
func (c *routeClaims) inspects(epID string) bool {
	if c.everywhere {
		return true
	}
	_, ok := c.inspected[epID]
	return ok
}

// sameRoutes reports whether a and b are one slice. The route registry builds
// a new sorted slice on every change and never writes to one it has handed
// out, so the slice a snapshot was built from standing unchanged means the
// routes have not changed. Checking this on every connection is what keeps a
// missed invalidation harmless, as the pools' config hash does: the
// resolver's invalidation hooks are not called when a route is deleted.
func sameRoutes(a, b []*gateonv1.Route) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// currentClaims returns the claims for the route store's routes now,
// rebuilding them only when the routes have changed.
func (r *Resolver) currentClaims() *routeClaims {
	routes := r.routeStore.List(context.Background())
	c := r.claims.Load()
	if c == nil || !sameRoutes(c.routes, routes) {
		c = newRouteClaims(routes)
		r.claims.Store(c) // racing rebuilders store equal answers
	}
	return c
}

// OnlyTCPRoute returns ep's generic tcp route when nothing else is served on
// ep -- no HTTP, gRPC, GraphQL, ssh or rdp route lists it, and no HTTP-served
// route lists no entrypoint, which serves it everywhere -- and nil otherwise.
// Such an entrypoint has nothing to tell apart, so a connection can go to the
// route the moment it is accepted: no detection window, and a server-first
// backend greets at once.
func (r *Resolver) OnlyTCPRoute(ep *gateonv1.EntryPoint) TCPProxy {
	if r.currentClaims().inspects(ep.Id) {
		return nil
	}
	return r.ResolveTCP(ep, "")
}
