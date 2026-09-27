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
			resp := postAnalyzeConfig(t, tc.globalWAF, tc.routeWAF, tc.pausedWithoutWAF)
			if got := hasInsight(resp, "Web Application Firewall is disabled"); got != tc.disabled {
				t.Errorf("WAF-disabled insight reported = %v, want %v", got, tc.disabled)
			}
			if got := hasInsight(resp, "Web Application Firewall covers"); got != tc.partial {
				t.Errorf("partial-coverage insight reported = %v, want %v", got, tc.partial)
			}
		})
	}
}

// postAnalyzeConfig asks the real handler, wired to real route and middleware
// services, for an analysis of a gateway whose routes do or do not attach a WAF.
func postAnalyzeConfig(t *testing.T, globalWAF bool, routeWAF []bool, pausedWithoutWAF bool) aiAnalysisResponse {
	t.Helper()
	ctx, dir := t.Context(), t.TempDir()
	globals := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	gc := proto.Clone(globals.Get(ctx)).(*gateonv1.GlobalConfig)
	gc.Waf.Enabled = globalWAF
	must(t, globals.Update(ctx, gc))

	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	mws := config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))
	must(t, mws.Update(ctx, &gateonv1.Middleware{Id: "edge-waf", Name: "edge-waf", Type: "waf"}))
	must(t, mws.Update(ctx, &gateonv1.Middleware{Id: "gzip", Name: "gzip", Type: "compress"}))
	for i, has := range routeWAF {
		rt := &gateonv1.Route{Id: fmt.Sprintf("rt-%d", i), Name: fmt.Sprintf("app-%d", i),
			Rule: fmt.Sprintf("PathPrefix(`/app%d`)", i), Middlewares: []string{"gzip"}}
		if has {
			rt.Middlewares = append(rt.Middlewares, "edge-waf")
		}
		must(t, routes.Update(ctx, rt))
	}
	if pausedWithoutWAF {
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
