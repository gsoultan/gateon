// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// reviewMalformedRules are the review's probe (2026-10-02 ops F2): rules the
// API used to store with 200 and the router read as match-all.
var reviewMalformedRules = []string{
	"PathPrefix(`/bad",
	"Host(`internal.example.com`",
	"Hots(`internal.example.com`)",
	"PathPrefx(`/admin`)",
}

func malformedRoute(id, rule string) *gateonv1.Route {
	return &gateonv1.Route{Id: id, Name: id, Type: "http", Rule: rule, ServiceId: "svc-legit"}
}

// A rule the router cannot read is refused on every transport that saves a
// route -- REST, gRPC and config import -- with the character it stops at,
// and nothing is stored (ADR 0043). The Connect handler does not serve
// UpdateRoute (ADR 0038), so there is no fourth writer to cover.
func TestARouteWhoseRuleDoesNotParseIsRefusedOnEveryTransport(t *testing.T) {
	for i, rule := range reviewMalformedRules {
		t.Run("REST/"+rule, func(t *testing.T) {
			a := newRouteAPI(t, auth.RoleAdmin)
			rt := malformedRoute("rest-bad", rule)
			code, body := a.putRouteRESTBody(t, rt)
			if code != http.StatusBadRequest || !strings.Contains(body, "at character") {
				t.Fatalf("PUT /v1/routes with %q: got %d %q, want 400 naming the position", rule, code, body)
			}
			if a.hasRoute(rt.Id) {
				t.Fatalf("route with rule %q was stored", rule)
			}
		})
		t.Run("gRPC/"+rule, func(t *testing.T) {
			a := newRouteAPI(t, auth.RoleAdmin)
			rt := malformedRoute("grpc-bad", rule)
			_, err := a.grpc.UpdateRoute(context.Background(), &gateonv1.UpdateRouteRequest{Route: rt})
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "at character") {
				t.Fatalf("gRPC UpdateRoute with %q: got %v, want InvalidArgument naming the position", rule, err)
			}
			if a.hasRoute(rt.Id) {
				t.Fatalf("route with rule %q was stored", rule)
			}
		})
		t.Run("import/"+rule, func(t *testing.T) {
			a := newRouteAPI(t, auth.RoleAdmin)
			good := malformedRoute("import-good", "PathPrefix(`/shop`)")
			bad := malformedRoute("import-bad", rule)
			errs := a.importRoutes(t, "/v1/config/import", good, bad)
			if len(errs) != 1 || !strings.Contains(errs[0], "import-bad") || !strings.Contains(errs[0], "at character") {
				t.Fatalf("import with %q: errors %v, want one naming import-bad and the position", rule, errs)
			}
			if a.hasRoute(bad.Id) || !a.hasRoute(good.Id) {
				t.Fatalf("import with %q: bad stored %v, good stored %v; want only the good route", rule, a.hasRoute(bad.Id), a.hasRoute(good.Id))
			}
			if errs := a.importRoutes(t, "/v1/config/validate", bad); len(errs) != 1 {
				t.Fatalf("validate with %q: errors %v, want the preflight to refuse it too (case %d)", rule, errs, i)
			}
		})
	}
}

func (a *routeAPI) putRouteRESTBody(t *testing.T, rt *gateonv1.Route) (int, string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"id": rt.Id, "name": rt.Name, "type": rt.Type, "rule": rt.Rule, "service_id": rt.ServiceId})
	if err != nil {
		t.Fatal(err)
	}
	return a.send(t, http.MethodPut, "/v1/routes", string(body))
}

// importRoutes posts routes to the import (or its validate preflight) and
// returns the errors it reports.
func (a *routeAPI) importRoutes(t *testing.T, path string, routes ...*gateonv1.Route) []string {
	t.Helper()
	list := make([]map[string]any, 0, len(routes))
	for _, rt := range routes {
		list = append(list, map[string]any{"id": rt.Id, "name": rt.Name, "type": rt.Type, "rule": rt.Rule, "service_id": rt.ServiceId})
	}
	body, err := json.Marshal(map[string]any{"routes": list})
	if err != nil {
		t.Fatal(err)
	}
	code, out := a.send(t, http.MethodPost, path, string(body))
	if code != http.StatusOK {
		t.Fatalf("POST %s: %d %s", path, code, out)
	}
	var res struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("POST %s: %v in %s", path, err, out)
	}
	return res.Errors
}

func (a *routeAPI) send(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, a.url+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(out)
}
