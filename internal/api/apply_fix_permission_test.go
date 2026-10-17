// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// permissionFixture is applyFixService with what every fixer below reads: a
// cors middleware on r1, a CORS and a WAF finding stored, an audit-only global
// WAF, and a WAF exception store over a migrated SQLite file.
type permissionFixture struct {
	svc     *ApiService
	routes  *config.RouteRegistry
	mws     *config.MiddlewareRegistry
	globals *config.GlobalRegistry
}

func newPermissionFixture(t *testing.T, corsOrigin string) permissionFixture {
	t.Helper()
	svc, routes, mws, globals := applyFixService(t)
	ctx := t.Context()
	mustSeed := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	mustSeed(mws.Update(ctx, &gateonv1.Middleware{Id: "cors-r1", Type: "cors",
		Config: map[string]string{"allowed_origins": "https://app.example"}}))
	mustSeed(routes.Update(ctx, &gateonv1.Route{Id: "r1", Name: "r1", Middlewares: []string{"cors-r1"},
		ServiceId: "svc", Type: "http", Rule: "Host(`r1.test`)"}))
	mustSeed(globals.Update(ctx, &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, AuditOnly: true}}))

	telemetry.RecordSecurityThreat(telemetry.SecurityThreat{ID: "cors-1", Type: "cors_violation", RouteID: "r1",
		Details: "Invalid CORS request from origin: " + corsOrigin + ". Allowed origins: [https://app.example]"})
	telemetry.RecordSecurityThreat(telemetry.SecurityThreat{ID: "waf-1", Type: "waf_block", SourceIP: "10.9.9.9",
		RequestURI: "/search?q=x", TriggeredRules: "[942100]"})
	telemetry.FlushThreats()

	sqlDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "waf.db"))
	mustSeed(err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	dialect := db.Dialect{Driver: db.DriverSQLite}
	mustSeed(db.Migrate(sqlDB, dialect))
	svc.WafExceptions = waf.NewExceptionStore(sqlDB, dialect)
	return permissionFixture{svc: svc, routes: routes, mws: mws, globals: globals}
}

// snapshot is everything a fixer could change, to prove a refusal wrote nothing.
func (f permissionFixture) snapshot(t *testing.T) []proto.Message {
	t.Helper()
	ctx := t.Context()
	rt, _ := f.routes.Get(ctx, "r1")
	mw, _ := f.mws.Get(ctx, "cors-r1")
	return []proto.Message{proto.Clone(rt), proto.Clone(mw), proto.Clone(f.globals.Get(ctx))}
}

func (f permissionFixture) unchanged(t *testing.T, before []proto.Message) {
	t.Helper()
	for i, now := range f.snapshot(t) {
		if !proto.Equal(before[i], now) {
			t.Errorf("a refused fix changed the configuration:\nbefore %v\nafter  %v", before[i], now)
		}
	}
	if n := len(f.svc.WafExceptions.All()); n != 0 {
		t.Errorf("a refused fix stored %d WAF exceptions", n)
	}
}

// permissionFixes are the fixers that change a resource other than
// diagnostics, each with the request the dashboard sends for it.
var permissionFixes = []struct {
	name string
	req  *gateonv1.ApplyRecommendationRequest
}{
	{"shadowed route (routes)", &gateonv1.ApplyRecommendationRequest{AnomalyType: "shadowed_route", Source: "r1"}},
	{"cors (middlewares)", &gateonv1.ApplyRecommendationRequest{AnomalyType: "cors_violation", ThreatId: "cors-1"}},
	{"waf exception (waf_rules)", &gateonv1.ApplyRecommendationRequest{AnomalyType: "waf_block", ThreatId: "waf-1"}},
	{"block country (global)", &gateonv1.ApplyRecommendationRequest{AnomalyType: "geofence_violation", Source: "RU"}},
	{"waf hardening (global)", &gateonv1.ApplyRecommendationRequest{AnomalyType: "security_vulnerability"}},
}

// TestApplyFixNeedsPermissionOnWhatItChanges: ApplyRecommendation is
// diagnostics:write, and every fixer here changes something else -- a route,
// a middleware, a WAF exception, the global configuration. A caller without
// write on that resource is refused, and nothing is written. The operator, who
// holds those permissions, is the control: the same fix succeeds for them, so
// the refusal is the permission check and not a fixture that cannot be fixed.
func TestApplyFixNeedsPermissionOnWhatItChanges(t *testing.T) {
	for _, fix := range permissionFixes {
		for _, caller := range []struct {
			name   string
			claims any
		}{
			{"viewer", &auth.Claims{ID: "v", Username: "viewer", Role: auth.RoleViewer}},
			{"unreadable claims", "not-claims"},
		} {
			t.Run(fix.name+"/"+caller.name, func(t *testing.T) {
				f := newPermissionFixture(t, "https://partner.example")
				before := f.snapshot(t)
				ctx := context.WithValue(t.Context(), middleware.UserContextKey, caller.claims)
				resp, err := f.svc.ApplyRecommendation(ctx, fix.req)
				if err != nil {
					t.Fatalf("ApplyRecommendation: %v", err)
				}
				if resp.GetSuccess() || !strings.Contains(resp.GetMessage(), "permission") {
					t.Errorf("success=%v message=%q, want a refusal for permission", resp.GetSuccess(), resp.GetMessage())
				}
				f.unchanged(t, before)
			})
		}
		t.Run(fix.name+"/operator", func(t *testing.T) {
			f := newPermissionFixture(t, "https://partner.example")
			ctx := context.WithValue(t.Context(), middleware.UserContextKey,
				&auth.Claims{ID: "o", Username: "operator", Role: auth.RoleOperator})
			resp, err := f.svc.ApplyRecommendation(ctx, fix.req)
			if err != nil || !resp.GetSuccess() {
				t.Errorf("operator: err=%v success=%v message=%q, want the fix applied", err, resp.GetSuccess(), resp.GetMessage())
			}
		})
	}
}

// TestCORSFixRefusesAnOriginThatIsNotOne: the origin the CORS fix writes is
// sliced out of a threat's Details, which reportCORSViolation builds from the
// raw Origin header -- the client's text. A header that is a list, a wildcard,
// or anything but scheme://host[:port] would become an allowed-origins entry
// the operator never chose: "*" allows every site, and a comma adds two.
func TestCORSFixRefusesAnOriginThatIsNotOne(t *testing.T) {
	for _, origin := range []string{
		"https://evil.example,https://other.example",
		"*",
		"https://*.example",
		"null",
		"https://evil.example/path",
		"https://evil.example?q=1",
		"https://user@evil.example",
		"https://evil .example",
		"javascript://evil.example",
		"https://",
	} {
		t.Run(origin, func(t *testing.T) {
			f := newPermissionFixture(t, origin)
			before := f.snapshot(t)
			resp, err := f.svc.ApplyRecommendation(t.Context(),
				&gateonv1.ApplyRecommendationRequest{AnomalyType: "cors_violation", ThreatId: "cors-1"})
			if err != nil {
				t.Fatalf("ApplyRecommendation: %v", err)
			}
			if resp.GetSuccess() {
				t.Errorf("origin %q was accepted: %s", origin, resp.GetMessage())
			}
			f.unchanged(t, before)
		})
	}

	f := newPermissionFixture(t, "https://partner.example:8443")
	resp, err := f.svc.ApplyRecommendation(t.Context(),
		&gateonv1.ApplyRecommendationRequest{AnomalyType: "cors_violation", ThreatId: "cors-1"})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("a well-formed origin was refused: err=%v message=%q", err, resp.GetMessage())
	}
	mw, _ := f.mws.Get(t.Context(), "cors-r1")
	if got := mw.GetConfig()["allowed_origins"]; got != "https://app.example,https://partner.example:8443" {
		t.Errorf("allowed_origins = %q", got)
	}
}
