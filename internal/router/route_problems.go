// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"context"
	"fmt"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/security/reputation"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Kinds of RouteProblem.
const (
	// ProblemRefuses is a route that answers every request 503: a security
	// middleware it names is missing or cannot be built, and it fails closed.
	ProblemRefuses = "refuses"
	// ProblemMatchesNothing is a route whose rule does not parse; it matches
	// no request.
	ProblemMatchesNothing = "matches_nothing"
)

// RouteProblem is why a route cannot serve as configured (ops OPS-N4). Both
// shapes used to surface only when a request reached the route -- after an
// upgrade, a rarely-hit callback route could fail for days unnoticed.
type RouteProblem struct {
	RouteID string `json:"routeId"`
	Route   string `json:"route"`
	Kind    string `json:"kind"`
	Reason  string `json:"reason"`
}

// ChainDeps are what a route's middleware chain is built with, as the proxy
// cache builds it.
type ChainDeps struct {
	Redis       redis.Client
	Middlewares config.MiddlewareStore
	Global      config.GlobalConfigStore
	Ebpf        ebpf.Manager
	Reputation  *reputation.IPReputationStore
}

// RouteProblems builds each enabled HTTP route's middlewares the way the
// router does and parses its rule, and reports the routes that would refuse
// every request or match none. Nothing is logged per route: the caller says
// it once.
func RouteProblems(ctx context.Context, routes []*gateonv1.Route, d ChainDeps) []RouteProblem {
	var out []RouteProblem
	for _, rt := range routes {
		if rt.GetDisabled() || isL4Route(rt.GetType()) {
			continue
		}
		if p, ok := routeProblem(ctx, rt, d); ok {
			out = append(out, p)
		}
	}
	return out
}

func routeProblem(ctx context.Context, rt *gateonv1.Route, d ChainDeps) (RouteProblem, bool) {
	p := RouteProblem{RouteID: rt.GetId(), Route: RouteLabel(rt)}
	if strings.TrimSpace(rt.GetRule()) != "" {
		if _, err := compileRule(rt.GetRule()); err != nil {
			p.Kind, p.Reason = ProblemMatchesNothing, "rule does not parse: "+err.Error()
			return p, true
		}
	}
	f := middleware.NewFactory(d.Redis, d.Global, d.Ebpf, d.Reputation, ".")
	f.SetRouteType(rt.GetType())
	f.SetRouteKey(rt.GetId())
	built := buildRouteMiddlewares(ctx, f, rt, d.Middlewares)
	if reasons := built.refusalReasons(); len(reasons) > 0 {
		p.Kind, p.Reason = ProblemRefuses, strings.Join(reasons, "; ")
		return p, true
	}
	return p, false
}

func isL4Route(t string) bool {
	t = strings.ToLower(strings.TrimSpace(t))
	return t == "tcp" || t == "udp"
}

// buildFailure is one middleware a route names that did not build.
type buildFailure struct {
	id, typ  string
	err      error // nil when the middleware does not exist
	security bool  // a security middleware fails the route closed
}

// routeBuild is what building a route's middlewares produced.
type routeBuild struct {
	user     []middleware.Middleware
	cors     middleware.Middleware
	hasCORS  bool
	hasWAF   bool
	failures []buildFailure
}

// buildRouteMiddlewares builds the middlewares rt names, in order.
//
// hasWAF records whether the route attached its own "waf" middleware and it
// built. It gates the gateway-wide WAF: a route with its own WAF is an explicit
// override and must not also run the global one. Set only on a successful
// Create, so a per-route WAF that fails to build leaves the global WAF covering
// the route -- a misconfigured override fails safe rather than open.
func buildRouteMiddlewares(ctx context.Context, f *middleware.Factory, rt *gateonv1.Route, store config.MiddlewareStore) routeBuild {
	var b routeBuild
	if store == nil {
		return b
	}
	label := RouteLabel(rt)
	for _, mid := range rt.Middlewares {
		mid = strings.TrimSpace(mid)
		if mid == "" {
			continue
		}
		conf, found := store.Get(ctx, mid)
		if !found || conf == nil {
			// A renamed or deleted middleware used to be skipped silently,
			// removing whatever it enforced. Treated as a security build
			// failure of unknown type, which fails closed.
			b.failures = append(b.failures, buildFailure{id: mid, security: true})
			continue
		}
		mw, err := f.Create(conf, label) //nolint:contextcheck // Create takes no context; the router has always called it this way.
		if err != nil {
			b.failures = append(b.failures, buildFailure{id: mid, typ: conf.Type, err: err, security: isSecurityMiddleware(conf.Type)})
			continue
		}
		b.add(conf.Type, mw)
	}
	return b
}

func (b *routeBuild) add(typ string, mw middleware.Middleware) {
	switch {
	case strings.EqualFold(typ, "cors") || strings.EqualFold(typ, "grpcweb"):
		if !b.hasCORS {
			b.cors, b.hasCORS = mw, true
		}
	default:
		if strings.EqualFold(typ, "waf") {
			b.hasWAF = true
		}
		b.user = append(b.user, mw)
	}
}

// refusing lists the middlewares whose failure fails the route closed.
func (b routeBuild) refusing() []string {
	var out []string
	for _, f := range b.failures {
		if f.security {
			out = append(out, f.id)
		}
	}
	return out
}

// refusalReasons says, per middleware that fails the route closed, why.
func (b routeBuild) refusalReasons() []string {
	var out []string
	for _, f := range b.failures {
		switch {
		case !f.security:
		case f.err == nil:
			out = append(out, fmt.Sprintf("middleware %q does not exist", f.id))
		default:
			out = append(out, fmt.Sprintf("%s middleware %q cannot be built: %v", f.typ, f.id, f.err))
		}
	}
	return out
}

// log writes what the router has always written for each failure: an error
// when the route fails closed, a warning when it serves without a cosmetic
// middleware.
func (b routeBuild) log(label string) {
	for _, f := range b.failures {
		switch {
		case f.err == nil:
			logger.L.LogError("route names a middleware that does not exist; "+
				"the route will refuse requests until it is fixed",
				"route", label, "middleware", f.id)
		case f.security:
			// Previously a bare `continue`: the middleware vanished from the
			// chain, nothing was logged, and the chain is cached until
			// invalidated -- so a transient failure was baked in.
			logger.L.LogError("security middleware failed to build; the route "+
				"will refuse requests rather than serve without it",
				"route", label, "middleware", f.id, "type", f.typ, "error", f.err)
		default:
			logger.L.LogWarn("middleware failed to build; the route will serve without it",
				"route", label, "middleware", f.id, "type", f.typ, "error", f.err)
		}
	}
}
