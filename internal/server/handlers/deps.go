// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/domain/canary"
	"github.com/gsoultan/gateon/internal/domain/entrypoint"
	"github.com/gsoultan/gateon/internal/domain/middleware"
	"github.com/gsoultan/gateon/internal/domain/route"
	"github.com/gsoultan/gateon/internal/domain/service"
	"github.com/gsoultan/gateon/internal/domain/tls"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/internal/server/mgmtorigin"
	"github.com/gsoultan/gateon/pkg/proxy"
)

// RouteStatsProvider returns target stats for a route. Nil if route not found.
type RouteStatsProvider func(routeID string) []proxy.TargetStats

// RouteProblemsProvider lists the routes that cannot serve as configured.
type RouteProblemsProvider func(ctx context.Context) []router.RouteProblem

// Deps holds dependencies for REST API handlers (avoids importing server package).
type Deps struct {
	RouteService   route.Service
	ServiceService service.Service
	EpService      entrypoint.Service
	MwService      middleware.Service
	TLSOptService  tls.Service
	CanaryService  canary.Service
	AuthManager    auth.Service
	// SetupToken is the one-time token the first-run connection test requires,
	// as Setup does; nil keeps the test closed.
	SetupToken         *auth.SetupToken
	Version            string
	StartTime          time.Time
	RouteStatsProvider RouteStatsProvider
	// RouteProblems, when set, supplies GET /v1/routes/problems (OPS-N4).
	RouteProblems RouteProblemsProvider
	// SecurityPosture, when set, supplies the report for GET /v1/security/posture.
	SecurityPosture SecurityPostureProvider
	// InvalidateAllProxies, when set, drops every cached route proxy so the
	// composed middleware chain is rebuilt on the next request. It is called
	// after a global-config change that affects chain composition (e.g. toggling
	// the global WAF or advanced-security middlewares, which are injected at
	// chain-build time in router.ApplyRouteMiddlewares).
	InvalidateAllProxies func()
	// MgmtOrigins decides which pages may open the management WebSockets with
	// the caller's session: the management origin and the configured CORS
	// origins. Nil allows the management origin only.
	MgmtOrigins *mgmtorigin.Policy
}
