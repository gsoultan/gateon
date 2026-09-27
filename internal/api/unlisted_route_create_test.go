// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// e2eRoutes is tests/e2e/config/routes.json's shape: HTTP routes on every
// entrypoint to one service, a gRPC route, and a TCP route on its own
// entrypoint.
func e2eRoutes() []*gateonv1.Route {
	return []*gateonv1.Route{
		{Id: "test-route", Name: "Test Route", Type: "http", Rule: "PathPrefix(`/test`)", ServiceId: "mock-service"},
		{Id: "ratelimit-route", Name: "Rate Limit Route", Type: "http", Rule: "PathPrefix(`/ratelimit`)", ServiceId: "mock-service"},
		{Id: "grpc-route", Name: "gRPC Route", Type: "grpc", Rule: "PathPrefix(`/test.TestService`)", ServiceId: "grpc-service"},
		{Id: "tcp-route", Name: "TCP Route", Type: "tcp", Entrypoints: []string{"tcp"}, Rule: "Host(`*`)", ServiceId: "tcp-service"},
	}
}

type unlistedFixture struct {
	svc    *ApiService
	routes *config.RouteRegistry
}

func newUnlistedFixture(t *testing.T, routes []*gateonv1.Route) unlistedFixture {
	t.Helper()
	ctx, dir := t.Context(), t.TempDir()
	eps := config.NewEntryPointRegistry(filepath.Join(dir, "entrypoints.json"))
	svcs := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	rts := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	for _, ep := range []*gateonv1.EntryPoint{
		{Id: "http-plain", Address: "127.0.0.1:8081", Type: gateonv1.EntryPoint_HTTP},
		{Id: "websecure", Name: "Public HTTPS", Address: "127.0.0.1:8443", Type: gateonv1.EntryPoint_HTTP},
		{Id: "tcp", Address: "127.0.0.1:8086", Type: gateonv1.EntryPoint_TCP},
	} {
		if err := eps.Update(ctx, ep); err != nil {
			t.Fatalf("seed entrypoint: %v", err)
		}
	}
	for _, s := range []*gateonv1.Service{
		{Id: "mock-service", Name: "Mock Service"}, {Id: "grpc-service"}, {Id: "tcp-service"},
		{Id: "svc-app", Name: "App"}, {Id: "svc-api", Name: "API"}, {Id: "svc-b"},
	} {
		if err := svcs.Update(ctx, s); err != nil {
			t.Fatalf("seed service: %v", err)
		}
	}
	for _, rt := range routes {
		if err := rts.Update(ctx, rt); err != nil {
			t.Fatalf("seed route: %v", err)
		}
	}
	svc := NewApiService(ApiServiceConfig{
		EntryPoints: eps, Services: svcs, Routes: rts,
		Middlewares: config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json")),
		Globals:     config.NewGlobalRegistry(filepath.Join(dir, "global.json")),
	})
	return unlistedFixture{svc: svc, routes: rts}
}

// unlistedFinding is what the dashboard sends for an unlisted_route finding on
// a request for path that arrived on entrypoint for host.
func unlistedFinding(path, entrypoint, host string) *gateonv1.ApplyRecommendationRequest {
	return &gateonv1.ApplyRecommendationRequest{
		AnomalyType: "unlisted_route", Source: "203.0.113.11",
		RequestUri: path, Entrypoint: entrypoint, Host: host,
	}
}

func (f unlistedFixture) apply(t *testing.T, ctx context.Context, req *gateonv1.ApplyRecommendationRequest) *gateonv1.ApplyRecommendationResponse {
	t.Helper()
	resp, err := f.svc.ApplyRecommendation(ctx, req)
	if err != nil {
		t.Fatalf("ApplyRecommendation: %v", err)
	}
	return resp
}

// routesWithRule returns the routes whose rule is exactly rule.
func (f unlistedFixture) routesWithRule(t *testing.T, rule string) []*gateonv1.Route {
	t.Helper()
	var out []*gateonv1.Route
	for _, rt := range f.routes.List(t.Context()) {
		if rt.GetRule() == rule {
			out = append(out, rt)
		}
	}
	return out
}

func (f unlistedFixture) routeIDs(t *testing.T) []string {
	t.Helper()
	var ids []string
	for _, rt := range f.routes.List(t.Context()) {
		ids = append(ids, rt.GetId())
	}
	slices.Sort(ids)
	return ids
}

// TestUnlistedRouteFixCreatesAPausedRouteForThePath: the fix answered success
// and created nothing. It must create a route for exactly the requested path,
// on the entrypoint the request arrived at, pointed at the service that serves
// that entrypoint -- and paused, so the path is still not served.
func TestUnlistedRouteFixCreatesAPausedRouteForThePath(t *testing.T) {
	f := newUnlistedFixture(t, e2eRoutes())
	resp := f.apply(t, t.Context(), unlistedFinding("/unlisted-path-1", "http-plain", "localhost:8081"))
	if !resp.GetSuccess() {
		t.Fatalf("the fix was refused: %s", resp.GetMessage())
	}

	created := f.routesWithRule(t, "Host(`localhost`) && Path(`/unlisted-path-1`)")
	if len(created) != 1 {
		t.Fatalf("routes with the path's rule: %d, want 1; message: %s", len(created), resp.GetMessage())
	}
	rt := created[0]
	if !rt.GetDisabled() || rt.GetServiceId() != "mock-service" || rt.GetName() != "unlisted localhost/unlisted-path-1" ||
		!slices.Equal(rt.GetEntrypoints(), []string{"http-plain"}) || rt.GetType() != "http" || rt.GetId() == "" {
		t.Errorf("created route = %v, want a paused http route \"unlisted localhost/unlisted-path-1\" on http-plain to mock-service", rt)
	}
	for _, want := range []string{`"unlisted localhost/unlisted-path-1"`, "paused", "Host(`localhost`) && Path(`/unlisted-path-1`)",
		"http-plain", "Mock Service (mock-service)", "the only service routed on entrypoint http-plain",
		"Those routes carry no middlewares, and neither does it."} {
		if !strings.Contains(resp.GetMessage(), want) {
			t.Errorf("message does not say %s: %s", want, resp.GetMessage())
		}
	}

	// Paused means served by nothing: the router must not select it.
	probe := &http.Request{Method: http.MethodGet, Host: "localhost:8081", URL: &url.URL{Path: "/unlisted-path-1"}, Header: http.Header{}}
	probe = probe.WithContext(context.WithValue(t.Context(), middleware.EntryPointIDContextKey, "http-plain"))
	if got := router.SelectRouteFromSlice(probe, f.routes.List(t.Context())); got != nil {
		t.Errorf("the new route serves the path before anyone enabled it: %s", router.RouteLabel(got))
	}
}

// TestUnlistedRouteFixAnswersASecondApplyTruthfully: the same finding applied
// again must neither fail with the store's duplicate-name error nor add a
// second route.
func TestUnlistedRouteFixAnswersASecondApplyTruthfully(t *testing.T) {
	f := newUnlistedFixture(t, e2eRoutes())
	finding := unlistedFinding("/unlisted-path-2", "http-plain", "localhost:8081")
	if first := f.apply(t, t.Context(), finding); !first.GetSuccess() {
		t.Fatalf("first apply refused: %s", first.GetMessage())
	}
	second := f.apply(t, t.Context(), finding)
	if second.GetSuccess() {
		t.Errorf("a second apply claimed to create a route: %s", second.GetMessage())
	}
	if !strings.Contains(second.GetMessage(), `"unlisted localhost/unlisted-path-2" already exists`) || !strings.Contains(second.GetMessage(), "paused") {
		t.Errorf("second apply does not say the paused route exists: %s", second.GetMessage())
	}
	if n := len(f.routesWithRule(t, "Host(`localhost`) && Path(`/unlisted-path-2`)")); n != 1 {
		t.Errorf("routes for the path after two applies: %d, want 1", n)
	}
}

// TestUnlistedRouteFixPointsAtTheServiceOfTheHost: on an entrypoint serving
// several sites the most used service is often the wrong one; the service
// routed for the request's own host is the right guess.
func TestUnlistedRouteFixPointsAtTheServiceOfTheHost(t *testing.T) {
	f := newUnlistedFixture(t, []*gateonv1.Route{
		{Id: "app", Rule: "Host(`app.example.com`) && PathPrefix(`/app`)", ServiceId: "svc-app", Entrypoints: []string{"websecure"}},
		{Id: "api-1", Rule: "Host(`api.example.com`) && PathPrefix(`/v1`)", ServiceId: "svc-api", Entrypoints: []string{"websecure"}},
		{Id: "api-2", Rule: "Host(`api.example.com`) && PathPrefix(`/v2`)", ServiceId: "svc-api", Entrypoints: []string{"websecure"}},
	})
	// The finding names the entrypoint by the label traces carry: its name.
	resp := f.apply(t, t.Context(), unlistedFinding("/new-page", "Public HTTPS", "app.example.com:8443"))
	if !resp.GetSuccess() {
		t.Fatalf("the fix was refused: %s", resp.GetMessage())
	}
	created := f.routesWithRule(t, "Host(`app.example.com`) && Path(`/new-page`)")
	if len(created) != 1 || created[0].GetServiceId() != "svc-app" || !slices.Equal(created[0].GetEntrypoints(), []string{"websecure"}) {
		t.Fatalf("created %v, want one route on websecure to svc-app", created)
	}
	if !strings.Contains(resp.GetMessage(), "the only service routed for host app.example.com on entrypoint Public HTTPS") {
		t.Errorf("message does not say why svc-app: %s", resp.GetMessage())
	}
}

// TestUnlistedRouteFixSaysWhenEveryRouteThereIsForAnotherHost: with no route
// for the request's host and none that serves any host, the choice is the
// weakest one the fix makes, and the answer has to say so.
func TestUnlistedRouteFixSaysWhenEveryRouteThereIsForAnotherHost(t *testing.T) {
	f := newUnlistedFixture(t, []*gateonv1.Route{
		{Id: "api-1", Rule: "Host(`api.example.com`) && PathPrefix(`/v1`)", ServiceId: "svc-api", Entrypoints: []string{"websecure"}},
	})
	resp := f.apply(t, t.Context(), unlistedFinding("/new-page", "websecure", "app.example.com"))
	if !resp.GetSuccess() {
		t.Fatalf("the fix was refused: %s", resp.GetMessage())
	}
	if created := f.routesWithRule(t, "Host(`app.example.com`) && Path(`/new-page`)"); len(created) != 1 || created[0].GetServiceId() != "svc-api" {
		t.Fatalf("created %v, want one route to svc-api", created)
	}
	if !strings.Contains(resp.GetMessage(), "on entrypoint Public HTTPS, where every route names another host") {
		t.Errorf("message does not say the only routes there are for other hosts: %s", resp.GetMessage())
	}
}

// TestUnlistedRouteFixFallsBackToTheMostUsedService: when more than one service
// serves the entrypoint, the one most of its routes use, and the message says
// it was a choice.
func TestUnlistedRouteFixFallsBackToTheMostUsedService(t *testing.T) {
	f := newUnlistedFixture(t, []*gateonv1.Route{
		{Id: "a1", Rule: "PathPrefix(`/a`)", ServiceId: "svc-b"},
		{Id: "a2", Rule: "PathPrefix(`/b`)", ServiceId: "svc-b"},
		{Id: "b1", Rule: "PathPrefix(`/c`)", ServiceId: "svc-api"},
		// Paused routes serve nothing and do not count.
		{Id: "p1", Rule: "PathPrefix(`/d`)", ServiceId: "svc-api", Disabled: true},
		{Id: "p2", Rule: "PathPrefix(`/e`)", ServiceId: "svc-api", Disabled: true},
	})
	resp := f.apply(t, t.Context(), unlistedFinding("/elsewhere", "http-plain", ""))
	if !resp.GetSuccess() {
		t.Fatalf("the fix was refused: %s", resp.GetMessage())
	}
	if created := f.routesWithRule(t, "Path(`/elsewhere`)"); len(created) != 1 || created[0].GetServiceId() != "svc-b" {
		t.Fatalf("created %v, want one route to svc-b", created)
	}
	if !strings.Contains(resp.GetMessage(), "the most used of the 2 services routed on entrypoint http-plain: 2 of those 3 routes point at it") {
		t.Errorf("message does not explain the choice: %s", resp.GetMessage())
	}
}

// TestUnlistedRouteFixBreaksATieTheSameWayEveryTime: map order must not
// decide which service a route points at.
func TestUnlistedRouteFixBreaksATieTheSameWayEveryTime(t *testing.T) {
	for range 20 {
		f := newUnlistedFixture(t, []*gateonv1.Route{
			{Id: "b1", Rule: "PathPrefix(`/b`)", ServiceId: "svc-b"},
			{Id: "a1", Rule: "PathPrefix(`/a`)", ServiceId: "svc-api"},
		})
		f.apply(t, t.Context(), unlistedFinding("/tied", "http-plain", ""))
		if created := f.routesWithRule(t, "Path(`/tied`)"); len(created) != 1 || created[0].GetServiceId() != "svc-api" {
			t.Fatalf("created %v, want one route to svc-api, the lower id", created)
		}
	}
}

// TestUnlistedRouteFixLeavesAnAlreadyRoutedPathAlone: a finding outlives the
// moment it describes; if a route answers the path by now, adding another
// would only shadow or duplicate it.
func TestUnlistedRouteFixLeavesAnAlreadyRoutedPathAlone(t *testing.T) {
	f := newUnlistedFixture(t, e2eRoutes())
	before := f.routeIDs(t)
	resp := f.apply(t, t.Context(), unlistedFinding("/test/deeper", "http-plain", "localhost:8081"))
	if resp.GetSuccess() {
		t.Errorf("claimed to create a route for a path Test Route already serves: %s", resp.GetMessage())
	}
	if !strings.Contains(resp.GetMessage(), `already routed by "Test Route"`) {
		t.Errorf("message does not name the route that serves it: %s", resp.GetMessage())
	}
	if after := f.routeIDs(t); !slices.Equal(before, after) {
		t.Errorf("routes changed: %v -> %v", before, after)
	}
}

// TestUnlistedRouteFixRefusesWhatItCannotRouteSafely: each of these is refused
// with a reason and leaves the configuration exactly as it was.
func TestUnlistedRouteFixRefusesWhatItCannotRouteSafely(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *gateonv1.ApplyRecommendationRequest
		want string
	}{
		{"no path (what the dashboard used to send)", unlistedFinding("", "http-plain", ""), "does not say which path"},
		{"a backtick that would end the rule", unlistedFinding("/a`) || PathPrefix(`/", "http-plain", ""), "cannot be written as a route rule"},
		{"an OR the rule parser splits on", unlistedFinding("/a||b", "http-plain", ""), "cannot be written as a route rule"},
		{"a double quote", unlistedFinding(`/a"b`, "http-plain", ""), "cannot be written as a route rule"},
		{"a control character", unlistedFinding("/a\nb", "http-plain", ""), "cannot be written as a route rule"},
		{"a scanner's trap path", unlistedFinding("/.env", "http-plain", ""), "only scanners ask for"},
		{"a trap path reached by dot segments", unlistedFinding("/x/../.env", "http-plain", ""), "only scanners ask for"},
		{"a path too long to be one", unlistedFinding("/"+strings.Repeat("a", maxUnlistedRoutePathLen), "http-plain", ""), "too long"},
		{"no entrypoint", unlistedFinding("/fine", "", ""), "does not say which entrypoint"},
		{"an entrypoint that is gone", unlistedFinding("/fine", "gone", ""), "no longer exists"},
		{"a TCP entrypoint", unlistedFinding("/fine", "tcp", ""), "not routed by path"},
		{"a host that would end the rule", unlistedFinding("/fine", "http-plain", "a`) || PathPrefix(`/"), "cannot be written as a route rule"},
		{"a host with a space", unlistedFinding("/fine", "http-plain", "a b"), "cannot be written as a route rule"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newUnlistedFixture(t, e2eRoutes())
			before := f.routeIDs(t)
			resp := f.apply(t, t.Context(), tc.req)
			if resp.GetSuccess() || !strings.Contains(resp.GetMessage(), tc.want) {
				t.Errorf("success=%v message=%q, want a refusal saying %q", resp.GetSuccess(), resp.GetMessage(), tc.want)
			}
			if after := f.routeIDs(t); !slices.Equal(before, after) {
				t.Errorf("routes changed: %v -> %v", before, after)
			}
		})
	}
}

// TestUnlistedRouteFixRefusesAnEntrypointWithNoService: with nothing routed
// there, any service would be a guess with nothing behind it.
func TestUnlistedRouteFixRefusesAnEntrypointWithNoService(t *testing.T) {
	f := newUnlistedFixture(t, []*gateonv1.Route{
		{Id: "elsewhere", Rule: "PathPrefix(`/x`)", ServiceId: "svc-b", Entrypoints: []string{"http-plain"}},
	})
	resp := f.apply(t, t.Context(), unlistedFinding("/fine", "websecure", ""))
	if resp.GetSuccess() || !strings.Contains(resp.GetMessage(), "No service is routed on entrypoint Public HTTPS") {
		t.Errorf("success=%v message=%q, want a refusal naming the empty entrypoint", resp.GetSuccess(), resp.GetMessage())
	}
	if n := len(f.routesWithRule(t, "Path(`/fine`)")); n != 0 {
		t.Errorf("created %d routes", n)
	}
}

// TestUnlistedRouteFixNeedsPermissionToChangeRoutes: the fix creates a route,
// so it asks for what the Routes API asks for. ApplyRecommendation's own
// permission is diagnostics:write, which a custom role can hold without
// routes:write.
func TestUnlistedRouteFixNeedsPermissionToChangeRoutes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims any
	}{
		{"a role that may not write routes", &auth.Claims{ID: "v", Username: "viewer", Role: auth.RoleViewer}},
		{"claims that cannot be read", "not-claims"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newUnlistedFixture(t, e2eRoutes())
			ctx := context.WithValue(t.Context(), middleware.UserContextKey, tc.claims)
			resp := f.apply(t, ctx, unlistedFinding("/unlisted-path-3", "http-plain", ""))
			if resp.GetSuccess() || !strings.Contains(resp.GetMessage(), "permission to change routes") {
				t.Errorf("success=%v message=%q, want a refusal for permission", resp.GetSuccess(), resp.GetMessage())
			}
			if n := len(f.routesWithRule(t, "Path(`/unlisted-path-3`)")); n != 0 {
				t.Errorf("created %d routes without permission to", n)
			}
		})
	}

	operator := context.WithValue(t.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "o", Username: "operator", Role: auth.RoleOperator})
	f := newUnlistedFixture(t, e2eRoutes())
	if resp := f.apply(t, operator, unlistedFinding("/unlisted-path-3", "http-plain", "")); !resp.GetSuccess() {
		t.Errorf("an operator, who may write routes, was refused: %s", resp.GetMessage())
	}
}

// TestHoneypotAndScannerFindingsCreateNoRoutes: a honeypot or scanner finding
// carries the same path and entrypoint as an unlisted route, and routing it
// would expose exactly what the scanner was looking for.
func TestHoneypotAndScannerFindingsCreateNoRoutes(t *testing.T) {
	for _, typ := range []string{"honeypot_triggered", "honeypot_hit", "security_scan", "scanner"} {
		t.Run(typ, func(t *testing.T) {
			f := newUnlistedFixture(t, e2eRoutes())
			before := f.routeIDs(t)
			req := unlistedFinding("/wp-admin/setup.php", "http-plain", "localhost:8081")
			req.AnomalyType = typ
			resp := f.apply(t, t.Context(), req)
			if after := f.routeIDs(t); !slices.Equal(before, after) {
				t.Errorf("a %s finding created a route: %v -> %v (%s)", typ, before, after, resp.GetMessage())
			}
			if strings.Contains(resp.GetMessage(), "Created route") {
				t.Errorf("a %s finding reported creating a route: %s", typ, resp.GetMessage())
			}
		})
	}
}

// TestFindingTypesWithoutAFixSayNotImplemented: the dashboard offered the
// button on these (the AI analysis review counted nine), and the click could
// only answer that nothing was done. The answer stays honest and changes
// nothing; the dashboard no longer offers it (automaticFixes.ts).
func TestFindingTypesWithoutAFixSayNotImplemented(t *testing.T) {
	for _, typ := range []string{
		"neural_sentinel", "graph_coordinated_fp", "honeypot_triggered", "reputation_hit",
		"suspicious_activity", "coordinated_attack", "system_integrity_violation",
		"configuration_recommendation", "honeypot_hit",
	} {
		t.Run(typ, func(t *testing.T) {
			stores := newFixStores(t)
			svc := NewApiService(ApiServiceConfig{Routes: stores.routes, Middlewares: stores.mws, Globals: stores.globals})
			before := stores.snapshot(t.Context(), t)
			resp, err := svc.ApplyRecommendation(t.Context(), &gateonv1.ApplyRecommendationRequest{
				AnomalyType: typ, Source: "203.0.113.11", RequestUri: "/x", Entrypoint: "http-plain",
			})
			if err != nil {
				t.Fatalf("ApplyRecommendation: %v", err)
			}
			if resp.GetSuccess() || !strings.Contains(resp.GetMessage(), "not implemented") {
				t.Errorf("success=%v message=%q, want an honest not-implemented", resp.GetSuccess(), resp.GetMessage())
			}
			if _, offered := recommendationFixes[typ]; offered {
				t.Errorf("%s has a fix registered", typ)
			}
			if after := stores.snapshot(t.Context(), t); string(before) != string(after) {
				t.Error("the configuration changed")
			}
		})
	}
}

// TestUnlistedRouteDetectorSaysWhereTheRequestArrived: the fix needs the path,
// the entrypoint and the host, and the trace is the only place they are known.
// The finding used to carry the path alone, with the client's address as its
// source -- which the dashboard sent as if it were the path.
func TestUnlistedRouteDetectorSaysWhereTheRequestArrived(t *testing.T) {
	// Private addresses: the detector resolves each one's location, and a
	// public one would be looked up over the network.
	data := &DiagnosticData{Traces: []*telemetry.TraceRecord{
		{ServiceName: "gateon-Public HTTPS", Path: "/new-page", Host: "app.example.com:8443", SourceIP: "10.0.0.7"},
		{ServiceName: "gateon-http-plain", Path: "/.env", Host: "localhost:8081", SourceIP: "10.0.0.8"},
		{ServiceName: "Test Route", Path: "/test", Host: "localhost:8081", SourceIP: "10.0.0.9"},
	}}
	got := (&UnlistedRouteDetector{}).Detect(t.Context(), data)
	if len(got) != 2 {
		t.Fatalf("findings: %d, want 2 (the routed request is not one): %v", len(got), got)
	}
	for i, want := range []*gateonv1.Anomaly{
		{Type: "unlisted_route", Source: "10.0.0.7", RequestUri: "/new-page", Entrypoint: "Public HTTPS", Host: "app.example.com:8443"},
		{Type: "honeypot_triggered", Source: "10.0.0.8", RequestUri: "/.env", Entrypoint: "http-plain", Host: "localhost:8081"},
	} {
		a := got[i]
		if a.GetType() != want.GetType() || a.GetSource() != want.GetSource() || a.GetRequestUri() != want.GetRequestUri() ||
			a.GetEntrypoint() != want.GetEntrypoint() || a.GetHost() != want.GetHost() {
			t.Errorf("finding %d = {type %q source %q path %q entrypoint %q host %q}, want %v",
				i, a.GetType(), a.GetSource(), a.GetRequestUri(), a.GetEntrypoint(), a.GetHost(), want)
		}
	}
}

// TestUnlistedRouteFixAnswersOnlyTheRequestsHost: a Path rule on its own
// answers that path on every host the entrypoint serves, so once enabled the
// route would expose the service under hosts nobody asked about. With the host
// the request named, it answers that host alone.
func TestUnlistedRouteFixAnswersOnlyTheRequestsHost(t *testing.T) {
	f := newUnlistedFixture(t, e2eRoutes())
	if resp := f.apply(t, t.Context(), unlistedFinding("/new-page", "http-plain", "App.Example.com:8081")); !resp.GetSuccess() {
		t.Fatalf("the fix was refused: %s", resp.GetMessage())
	}
	created := f.routesWithRule(t, "Host(`app.example.com`) && Path(`/new-page`)")
	if len(created) != 1 {
		t.Fatalf("no route scoped to the request's host was created")
	}
	m := router.GetMatcher(created[0].GetRule())
	for host, want := range map[string]bool{"app.example.com": true, "app.example.com:8081": true, "other.example.com": false} {
		req := &http.Request{Method: http.MethodGet, Host: host, URL: &url.URL{Path: "/new-page"}, Header: http.Header{}}
		if got := m.Match(req); got != want {
			t.Errorf("the route's rule matches host %s: %v, want %v", host, got, want)
		}
	}
}

// TestUnlistedRouteFixSaysWhenNoHostWasRecorded: a trace written before hosts
// were recorded leaves the route answering every host; the answer says so.
func TestUnlistedRouteFixSaysWhenNoHostWasRecorded(t *testing.T) {
	f := newUnlistedFixture(t, e2eRoutes())
	resp := f.apply(t, t.Context(), unlistedFinding("/any-host", "http-plain", ""))
	if !resp.GetSuccess() || len(f.routesWithRule(t, "Path(`/any-host`)")) != 1 {
		t.Fatalf("success=%v, want one Path-only route; message: %s", resp.GetSuccess(), resp.GetMessage())
	}
	if !strings.Contains(resp.GetMessage(), "No host was recorded for the request, so once enabled it answers this path for every host on the entrypoint.") {
		t.Errorf("message does not warn that the route answers every host: %s", resp.GetMessage())
	}
}

// TestUnlistedRouteFixCarriesTheMiddlewaresItsSiblingsShare: routes to the
// same service are guarded alike -- a WAF, authentication, a rate limit -- and a
// route enabled without them would be the one open door to that service. Only
// the routes that chose the service count; another service's do not.
func TestUnlistedRouteFixCarriesTheMiddlewaresItsSiblingsShare(t *testing.T) {
	f := newUnlistedFixture(t, []*gateonv1.Route{
		{Id: "a1", Rule: "PathPrefix(`/a`)", ServiceId: "svc-api", Middlewares: []string{"waf-1", "auth-1"}},
		{Id: "a2", Rule: "PathPrefix(`/b`)", ServiceId: "svc-api", Middlewares: []string{"waf-1", "auth-1"}},
		{Id: "b1", Rule: "PathPrefix(`/c`)", ServiceId: "svc-b", Middlewares: []string{"cors-1"}},
	})
	resp := f.apply(t, t.Context(), unlistedFinding("/guarded", "http-plain", "api.example.com"))
	created := f.routesWithRule(t, "Host(`api.example.com`) && Path(`/guarded`)")
	if !resp.GetSuccess() || len(created) != 1 {
		t.Fatalf("success=%v created=%v; message: %s", resp.GetSuccess(), created, resp.GetMessage())
	}
	if got := created[0].GetMiddlewares(); !slices.Equal(got, []string{"waf-1", "auth-1"}) {
		t.Errorf("middlewares = %v, want the ones every svc-api route carries, in their order", got)
	}
	if !strings.Contains(resp.GetMessage(), "It carries the middlewares those routes share: waf-1, auth-1.") {
		t.Errorf("message does not name the middlewares: %s", resp.GetMessage())
	}
}

// TestUnlistedRouteFixCopiesNoMiddlewaresWhenTheSiblingsDisagree: with no one
// list to copy, any choice would be a guess about security; it copies none and
// says they must be reviewed before the route is enabled.
func TestUnlistedRouteFixCopiesNoMiddlewaresWhenTheSiblingsDisagree(t *testing.T) {
	f := newUnlistedFixture(t, []*gateonv1.Route{
		{Id: "a1", Rule: "PathPrefix(`/a`)", ServiceId: "svc-api", Middlewares: []string{"waf-1", "auth-1"}},
		{Id: "a2", Rule: "PathPrefix(`/b`)", ServiceId: "svc-api", Middlewares: []string{"waf-1"}},
	})
	resp := f.apply(t, t.Context(), unlistedFinding("/unsure", "http-plain", "api.example.com"))
	created := f.routesWithRule(t, "Host(`api.example.com`) && Path(`/unsure`)")
	if !resp.GetSuccess() || len(created) != 1 {
		t.Fatalf("success=%v created=%v; message: %s", resp.GetSuccess(), created, resp.GetMessage())
	}
	if got := created[0].GetMiddlewares(); len(got) != 0 {
		t.Errorf("middlewares = %v, want none when the routes disagree", got)
	}
	if !strings.Contains(resp.GetMessage(), "review its middlewares before enabling it") {
		t.Errorf("message does not say the middlewares need review: %s", resp.GetMessage())
	}
}

// TestUnlistedRouteDetectorFoldsRepeatsIntoOneFinding: the detector reported
// one finding per trace, so one scanner sweeping one path filled the Anomaly
// Engine with copies of the same thing. Requests for the same path,
// entrypoint and host are one finding now, with how many there were, the
// latest one's time and client, and the clients seen. A honeypot keeps a
// finding per client, because each one that springs the trap is its own actor.
func TestUnlistedRouteDetectorFoldsRepeatsIntoOneFinding(t *testing.T) {
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	at := func(path, host, ip string, sec int) *telemetry.TraceRecord {
		return &telemetry.TraceRecord{ServiceName: "gateon-http-plain", Path: path, Host: host, SourceIP: ip,
			Timestamp: t0.Add(time.Duration(sec) * time.Second)}
	}
	got := (&UnlistedRouteDetector{}).Detect(t.Context(), &DiagnosticData{Traces: []*telemetry.TraceRecord{
		at("/a", "localhost:8081", "10.0.0.1", 0),
		at("/a", "localhost:8081", "10.0.0.2", 1),
		at("/a", "localhost:8081", "10.0.0.1", 2),
		at("/a", "other.example", "10.0.0.3", 1),
		at("/b", "localhost:8081", "10.0.0.1", 0),
		at("/.env", "localhost:8081", "10.0.0.4", 0),
		at("/.env", "localhost:8081", "10.0.0.5", 0),
		at("/.env", "localhost:8081", "10.0.0.4", 3),
	}})
	if len(got) != 5 {
		t.Fatalf("findings: %d, want 5 (one per path, entrypoint and host; a trap's per client)", len(got))
	}
	a := got[0]
	if a.GetRequestUri() != "/a" || a.GetHost() != "localhost:8081" || a.GetOccurrences() != 3 ||
		a.GetSource() != "10.0.0.1" || a.GetTimestamp() != t0.Add(2*time.Second).Format(time.RFC3339) ||
		!slices.Equal(a.GetSourceIps(), []string{"10.0.0.1", "10.0.0.2"}) {
		t.Errorf("folded /a = {occurrences %d, source %q, time %q, sources %v}, want 3, the latest 10.0.0.1 at +2s, both clients",
			a.GetOccurrences(), a.GetSource(), a.GetTimestamp(), a.GetSourceIps())
	}
	traps := 0
	for _, f := range got {
		if f.GetType() == "honeypot_triggered" {
			traps++
			if f.GetSource() == "10.0.0.4" && f.GetOccurrences() != 2 {
				t.Errorf("10.0.0.4 sprang the trap twice; occurrences = %d", f.GetOccurrences())
			}
		}
	}
	if traps != 2 {
		t.Errorf("honeypot findings: %d, want one per client (2)", traps)
	}
}

// TestUnlistedRouteDetectorBoundsWhatAFindingKeeps: a thousand clients on one
// path are one finding, which lists no more than maxFindingSources of them.
func TestUnlistedRouteDetectorBoundsWhatAFindingKeeps(t *testing.T) {
	traces := make([]*telemetry.TraceRecord, 0, 1000)
	for i := range 1000 {
		traces = append(traces, &telemetry.TraceRecord{ServiceName: "gateon-http-plain", Path: "/sweep",
			SourceIP: fmt.Sprintf("10.1.%d.%d", i/250, i%250), Timestamp: time.Unix(int64(i), 0)})
	}
	got := (&UnlistedRouteDetector{}).Detect(t.Context(), &DiagnosticData{Traces: traces})
	if len(got) != 1 {
		t.Fatalf("findings: %d, want 1", len(got))
	}
	if got[0].GetOccurrences() != 1000 || len(got[0].GetSourceIps()) != maxFindingSources {
		t.Errorf("occurrences %d, sources listed %d; want 1000 and %d",
			got[0].GetOccurrences(), len(got[0].GetSourceIps()), maxFindingSources)
	}
}

// TestAFoldedFindingIsMitigatedOnlyWhenEveryClientIs: blocking one of a
// path's clients leaves the others active, so the finding stays active until
// every client it stands for is blocked.
func TestAFoldedFindingIsMitigatedOnlyWhenEveryClientIs(t *testing.T) {
	blocked := []*gateonv1.Middleware{{Type: "ipfilter", Config: map[string]string{"deny_list": "10.0.0.1"}}}
	trace := func(ip string, sec int) *telemetry.TraceRecord {
		return &telemetry.TraceRecord{ServiceName: "gateon-http-plain", Path: "/m", SourceIP: ip,
			Timestamp: time.Unix(int64(sec), 0)}
	}
	for _, tc := range []struct {
		name   string
		traces []*telemetry.TraceRecord
		want   bool
	}{
		{"one client, blocked", []*telemetry.TraceRecord{trace("10.0.0.1", 0), trace("10.0.0.1", 1)}, true},
		{"a blocked client last, an open one before", []*telemetry.TraceRecord{trace("10.0.0.2", 0), trace("10.0.0.1", 1)}, false},
		{"an open client last", []*telemetry.TraceRecord{trace("10.0.0.1", 0), trace("10.0.0.2", 1)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := (&UnlistedRouteDetector{}).Detect(t.Context(), &DiagnosticData{Traces: tc.traces, Middlewares: blocked})
			if len(got) != 1 || got[0].GetMitigated() != tc.want {
				t.Errorf("findings %d, mitigated %v; want one finding, mitigated %v", len(got), len(got) == 1 && got[0].GetMitigated(), tc.want)
			}
		})
	}
}
