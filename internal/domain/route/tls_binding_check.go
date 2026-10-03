// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package route

import (
	"cmp"
	"context"
	"fmt"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TLSBindingCheck refuses a route save that puts a tls_binding middleware on
// an HTTP entrypoint without TLS (ADR 0046). The middleware binds a session to
// the client certificate of the TLS connection that received it; over plain
// HTTP there is none, so every request carrying the session would be refused.
// It is a SaveGuard so it runs on the save every transport and config import
// share.
//
// A route that names no entrypoint is served on every one, so every HTTP
// entrypoint must have TLS. Whether an entrypoint asks for client certificates
// is not checked here: that can be decided per route by a TLS option, and a
// request without one is refused at runtime with the reason.
type TLSBindingCheck struct {
	middlewares config.MiddlewareStore
	entrypoints config.EntryPointStore
}

// NewTLSBindingCheck builds the check over the stores it reads.
func NewTLSBindingCheck(mws config.MiddlewareStore, eps config.EntryPointStore) *TLSBindingCheck {
	return &TLSBindingCheck{middlewares: mws, entrypoints: eps}
}

// AuthorizeRouteSave implements SaveGuard.
func (c *TLSBindingCheck) AuthorizeRouteSave(ctx context.Context, rt *gateonv1.Route) error {
	if c == nil || c.middlewares == nil || c.entrypoints == nil || rt == nil || !c.bindsTLSBinding(ctx, rt) {
		return nil
	}
	for _, ep := range c.routeEntrypoints(ctx, rt) {
		if isHTTPEntrypoint(ep) && !ep.GetTls().GetEnabled() {
			return fmt.Errorf("route %q uses a tls_binding middleware on entrypoint %q, which has no TLS: "+
				"tls_binding binds a session to the client certificate of a TLS connection, so over plain "+
				"HTTP it would refuse every session; serve the route on TLS entrypoints only, or remove "+
				"the middleware", cmp.Or(rt.GetName(), rt.GetId()), cmp.Or(ep.GetName(), ep.GetId()))
		}
	}
	return nil
}

func (c *TLSBindingCheck) bindsTLSBinding(ctx context.Context, rt *gateonv1.Route) bool {
	for _, id := range rt.GetMiddlewares() {
		if mw, ok := c.middlewares.Get(ctx, strings.TrimSpace(id)); ok && mw.GetType() == "tls_binding" {
			return true
		}
	}
	return false
}

// routeEntrypoints is the entrypoints rt is served on: those it names, or
// every one when it names none.
func (c *TLSBindingCheck) routeEntrypoints(ctx context.Context, rt *gateonv1.Route) []*gateonv1.EntryPoint {
	if len(rt.GetEntrypoints()) == 0 {
		return c.entrypoints.List(ctx)
	}
	var out []*gateonv1.EntryPoint
	for _, id := range rt.GetEntrypoints() {
		if ep, ok := c.entrypoints.Get(ctx, id); ok {
			out = append(out, ep)
		}
	}
	return out
}

// isHTTPEntrypoint reports whether ep runs HTTP middleware; a TCP or UDP one
// does not.
func isHTTPEntrypoint(ep *gateonv1.EntryPoint) bool {
	t := ep.GetType()
	return t != gateonv1.EntryPoint_TCP && t != gateonv1.EntryPoint_UDP
}
