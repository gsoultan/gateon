// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	dmw "github.com/gsoultan/gateon/internal/domain/middleware"
	"github.com/gsoultan/gateon/internal/domain/route"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestAnalyzeConfigCountsTheWAFsRoutesCarry holds the WAF insight to what the
// router runs.
//
// A route that attaches a "waf" middleware gets that WAF instead of the
// gateway-wide one (router.go skips the global WAF for it), so the global
// toggle is only half the answer. The advisory read only the toggle, and with
// it off told an operator whose every route runs its own WAF, as its top
// critical finding, that "No WAF is active".
func TestAnalyzeConfigCountsTheWAFsRoutesCarry(t *testing.T) {
	cases := []struct {
		name              string
		globalWAF         bool
		routeWAF          []bool // per route: attaches a "waf" middleware
		pausedWithoutWAF  bool   // plus a disabled route with no WAF, which serves nothing
		disabled, partial bool   // the insights expected
	}{
		{name: "no WAF anywhere", routeWAF: []bool{false, false}, disabled: true},
		{name: "every route runs its own WAF", routeWAF: []bool{true, true}},
		{name: "one of two routes runs its own WAF", routeWAF: []bool{true, false}, partial: true},
		{name: "a paused route without one", routeWAF: []bool{true, true}, pausedWithoutWAF: true},
		{name: "the gateway-wide WAF", globalWAF: true, routeWAF: []bool{false, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postAnalyzeConfig(t, advisorySetup{globalWAF: tc.globalWAF, routeWAF: tc.routeWAF, pausedWithoutWAF: tc.pausedWithoutWAF})
			if got := hasInsight(resp, "Web Application Firewall is disabled"); got != tc.disabled {
				t.Errorf("WAF-disabled insight reported = %v, want %v", got, tc.disabled)
			}
			if got := hasInsight(resp, "Web Application Firewall covers"); got != tc.partial {
				t.Errorf("partial-coverage insight reported = %v, want %v", got, tc.partial)
			}
		})
	}
}

// TestAnalyzeConfigNamesAnAuditOnlyWAF is T12: an audit-only WAF blocks
// nothing, and the advisory said nothing about it -- the global case produced
// no insight at all, and a route-level audit-only WAF, which replaces the
// enforcing global one on its route, was counted as coverage.
func TestAnalyzeConfigNamesAnAuditOnlyWAF(t *testing.T) {
	cases := []struct {
		name  string
		setup advisorySetup
		want  string // insight severity, "" for none
	}{
		{"global WAF audit-only", advisorySetup{globalWAF: true, globalAudit: true, routeWAF: []bool{false, false}}, insightCritical},
		{"route WAF audit-only beside the enforcing global", advisorySetup{globalWAF: true, routeAudit: true, routeWAF: []bool{true, false}}, insightWarning},
		{"enforcing everywhere", advisorySetup{globalWAF: true, routeWAF: []bool{true, false}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postAnalyzeConfig(t, tc.setup)
			got := ""
			for _, in := range resp.Insights {
				if strings.Contains(in.Title, "detecting only (audit)") {
					got = in.Severity
				}
			}
			if got != tc.want {
				t.Fatalf("audit-only insight severity = %q, want %q; insights: %+v", got, tc.want, resp.Insights)
			}
		})
	}
}

// TestAnalyzeConfigReadsBotCoverageFromTheRoutes: the advisory counted the
// global bot-management switch as coverage, but it only supplies defaults to
// the bot_management middleware and protects no route that lacks one.
func TestAnalyzeConfigReadsBotCoverageFromTheRoutes(t *testing.T) {
	cases := []struct {
		name  string
		setup advisorySetup
		want  string // the bot insight's title, "" for none
	}{
		{"global switch on, no route carries it", advisorySetup{globalBot: true, routeWAF: []bool{false, false}}, "Bot management covers no route"},
		{"one of two routes carries it", advisorySetup{routeWAF: []bool{false, false}, botRoutes: 1}, "Bot management covers 1 of 2 routes"},
		{"every route carries it", advisorySetup{routeWAF: []bool{false, false}, botRoutes: 2}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ""
			for _, in := range postAnalyzeConfig(t, tc.setup).Insights {
				if strings.HasPrefix(in.Title, "Bot management") {
					got = in.Title
				}
			}
			if got != tc.want {
				t.Fatalf("bot insight = %q, want %q", got, tc.want)
			}
		})
	}
}

// advisorySetup is the gateway postAnalyzeConfig builds.
type advisorySetup struct {
	globalWAF, globalAudit bool
	globalBot              bool   // the global bot-management switch
	routeWAF               []bool // per route: attaches a "waf" middleware
	routeAudit             bool   // that middleware is audit-only
	botRoutes              int    // the first n routes attach a bot_management middleware
	pausedWithoutWAF       bool
}

// postAnalyzeConfig asks the real handler, wired to real route and middleware
// services, for an analysis of a gateway whose routes do or do not attach a WAF.
func postAnalyzeConfig(t *testing.T, s advisorySetup) aiAnalysisResponse {
	t.Helper()
	ctx, dir := t.Context(), t.TempDir()
	globals := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	gc := proto.Clone(globals.Get(ctx)).(*gateonv1.GlobalConfig)
	gc.Waf.Enabled = s.globalWAF
	gc.Waf.AuditOnly = s.globalAudit
	gc.Waf.BotManagement = &gateonv1.BotManagementConfig{Enabled: s.globalBot}
	must(t, globals.Update(ctx, gc))

	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	mws := config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))
	wafCfg := map[string]string{}
	if s.routeAudit {
		wafCfg["audit_only"] = "true"
	}
	must(t, mws.Update(ctx, &gateonv1.Middleware{Id: "edge-waf", Name: "edge-waf", Type: "waf", Config: wafCfg}))
	must(t, mws.Update(ctx, &gateonv1.Middleware{Id: "gzip", Name: "gzip", Type: "compress"}))
	must(t, mws.Update(ctx, &gateonv1.Middleware{Id: "bots", Name: "bots", Type: "bot_management"}))
	for i, has := range s.routeWAF {
		rt := &gateonv1.Route{Id: fmt.Sprintf("rt-%d", i), Name: fmt.Sprintf("app-%d", i),
			Rule: fmt.Sprintf("PathPrefix(`/app%d`)", i), Middlewares: []string{"gzip"}}
		if has {
			rt.Middlewares = append(rt.Middlewares, "edge-waf")
		}
		if i < s.botRoutes {
			rt.Middlewares = append(rt.Middlewares, "bots")
		}
		must(t, routes.Update(ctx, rt))
	}
	if s.pausedWithoutWAF {
		must(t, routes.Update(ctx, &gateonv1.Route{Id: "rt-paused", Name: "paused", Disabled: true,
			Rule: "PathPrefix(`/old`)", Middlewares: []string{"gzip"}}))
	}
	d := &Deps{
		RouteService: route.NewService(routes, nil, logger.Default()),
		MwService:    dmw.NewService(mws, routes, nil, nil, nil, logger.Default()),
	}
	mux := http.NewServeMux()
	registerAIAdvisoryHandlers(mux, advisoryAPI{globals: globals}, d)

	req := httptest.NewRequest(http.MethodPost, "/v1/AnalyzeConfig", strings.NewReader(`{"focus":"security"}`))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "v-1", Username: "viewer", Role: auth.RoleViewer}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /v1/AnalyzeConfig = %d: %s", rr.Code, rr.Body.String())
	}
	var resp aiAnalysisResponse
	must(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return resp
}

// advisoryAPI serves the one GlobalAndAuthAPI method the advisory reads.
type advisoryAPI struct {
	GlobalAndAuthAPI
	globals config.GlobalConfigStore
}

func (a advisoryAPI) GetGlobals() config.GlobalConfigStore { return a.globals }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
