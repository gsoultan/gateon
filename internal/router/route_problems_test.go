// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestRouteProblemsNamesTheRoutesThatCannotServe is OPS-N4: after an
// upgrade, routes that now fail closed (503) or whose rule no longer parses
// (matching nothing) were reported nowhere until a request reached them.
// RouteProblems finds both without traffic, with the reason, and says nothing
// about a route that serves, a disabled one, or an L4 one.
func TestRouteProblemsNamesTheRoutesThatCannotServe(t *testing.T) {
	store := &stubMiddlewareStore{mws: map[string]*gateonv1.Middleware{
		"broken-auth": {Id: "broken-auth", Type: "auth"},
		"headers":     {Id: "headers", Type: "headers"},
	}}
	routes := []*gateonv1.Route{
		{Id: "ok", Rule: "PathPrefix(`/ok`)", Middlewares: []string{"headers"}},
		{Id: "fails-closed", Rule: "PathPrefix(`/a`)", Middlewares: []string{"broken-auth"}},
		{Id: "missing-mw", Rule: "PathPrefix(`/b`)", Middlewares: []string{"gone"}},
		{Id: "bad-rule", Rule: "PathPrefix(`/c`"},
		{Id: "paused", Disabled: true, Middlewares: []string{"broken-auth"}},
		{Id: "l4", Type: "tcp", Middlewares: []string{"broken-auth"}},
	}
	got := map[string]RouteProblem{}
	for _, p := range RouteProblems(t.Context(), routes, ChainDeps{Middlewares: store}) {
		got[p.RouteID] = p
	}
	want := map[string]string{"fails-closed": ProblemRefuses, "missing-mw": ProblemRefuses, "bad-rule": ProblemMatchesNothing}
	if len(got) != len(want) {
		t.Fatalf("problems = %+v, want exactly %v", got, want)
	}
	for id, kind := range want {
		if got[id].Kind != kind || got[id].Reason == "" {
			t.Errorf("%s: problem = %+v, want kind %s with a reason", id, got[id], kind)
		}
	}
	if !strings.Contains(got["missing-mw"].Reason, `"gone" does not exist`) {
		t.Errorf("missing middleware reason = %q", got["missing-mw"].Reason)
	}
	if !strings.Contains(got["fails-closed"].Reason, `auth middleware "broken-auth" cannot be built`) {
		t.Errorf("build failure reason = %q", got["fails-closed"].Reason)
	}
}

// TestRouteProblemsNamesATarpitBuiltOff: a tarpit stored before the save check
// with no threshold above 0 is built switched off, so its route keeps serving,
// undelayed -- and is reported, so the tarpit it lists is not taken to be
// running.
func TestRouteProblemsNamesATarpitBuiltOff(t *testing.T) {
	store := &stubMiddlewareStore{mws: map[string]*gateonv1.Middleware{
		"slow": {Id: "slow", Type: "tarpit", Config: map[string]string{"base_delay": "5s", "max_delay": "5s"}},
		"ok":   {Id: "ok", Type: "tarpit", Config: map[string]string{"threshold": "90", "base_delay": "5s", "max_delay": "5s"}},
	}}
	rt := &gateonv1.Route{Id: "tarpitted", Rule: "PathPrefix(`/t`)", Middlewares: []string{"slow"}}
	routes := []*gateonv1.Route{rt, {Id: "fine", Rule: "PathPrefix(`/f`)", Middlewares: []string{"ok"}}}
	got := RouteProblems(t.Context(), routes, ChainDeps{Middlewares: store})
	if len(got) != 1 || got[0].RouteID != "tarpitted" || got[0].Kind != ProblemMiddlewareOff ||
		!strings.Contains(got[0].Reason, `tarpit middleware "slow" is off`) ||
		!strings.Contains(got[0].Reason, "threshold above 0") {
		t.Fatalf("problems = %+v, want only tarpitted, %s, naming the tarpit and why", got, ProblemMiddlewareOff)
	}

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	req := httptest.NewRequest(http.MethodGet, "http://x/t", nil)
	req.RemoteAddr = "100.64.95.1:4444"
	id := telemetry.GetReputationID(req)
	telemetry.DecreaseReputation(id, 50, "test: tarpit built off")
	t.Cleanup(func() { telemetry.ResetReputation(id) })
	rec := httptest.NewRecorder()
	start := time.Now()
	ApplyRouteMiddlewares(backend, rt, nil, store, nil, nil, nil).ServeHTTP(rec, req)
	if took := time.Since(start); rec.Code != http.StatusTeapot || took >= 5*time.Second {
		t.Errorf("status %d after %v; want the backend's answer, undelayed", rec.Code, took)
	}
}

// TestRouteProblemsAgreesWithTheChainTheRouterBuilds holds the report to the
// router: a route reported as refusing answers 503 through
// ApplyRouteMiddlewares, and one not reported reaches the backend.
func TestRouteProblemsAgreesWithTheChainTheRouterBuilds(t *testing.T) {
	store := &stubMiddlewareStore{mws: map[string]*gateonv1.Middleware{
		"broken-auth": {Id: "broken-auth", Type: "auth"},
	}}
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	for _, tc := range []struct {
		rt      *gateonv1.Route
		refuses bool
	}{
		{&gateonv1.Route{Id: "agree-refuses", Middlewares: []string{"broken-auth"}}, true},
		{&gateonv1.Route{Id: "agree-serves"}, false},
	} {
		reported := len(RouteProblems(t.Context(), []*gateonv1.Route{tc.rt}, ChainDeps{Middlewares: store})) > 0
		rec := httptest.NewRecorder()
		ApplyRouteMiddlewares(backend, tc.rt, nil, store, nil, nil, nil).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/", nil))
		if reported != tc.refuses || (rec.Code == http.StatusServiceUnavailable) != tc.refuses {
			t.Errorf("%s: reported=%v, status=%d; want refusing=%v in both", tc.rt.Id, reported, rec.Code, tc.refuses)
		}
	}
}
