// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var operatorClaims = &auth.Claims{ID: "op-1", Username: "operator", Role: auth.RoleOperator}

// readGlobalJSON is GET /v1/global decoded into a generic object, which is
// what the dashboard holds and edits before it sends the whole thing back.
func (a *adminAPI) readGlobalJSON(t *testing.T) map[string]any {
	t.Helper()
	code, body := a.do(t, http.MethodGet, "/v1/global", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/global: %d %s", code, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (a *adminAPI) putGlobalJSON(t *testing.T, conf map[string]any) (int, string) {
	t.Helper()
	body, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	code, out := a.do(t, http.MethodPut, "/v1/global", "application/json", body)
	return code, string(out)
}

func section(t *testing.T, conf map[string]any, name string) map[string]any {
	t.Helper()
	s, ok := conf[name].(map[string]any)
	if !ok {
		s = map[string]any{}
		conf[name] = s
	}
	return s
}

// TestOperatorCannotSwitchAuthenticationOffOverREST is A2 as it was exploited:
// an operator's PUT /v1/global with authentication off and the management API
// public returned 200, after which an anonymous request reset the
// administrator's password. It is now 403, names the fields, and changes
// nothing.
func TestOperatorCannotSwitchAuthenticationOffOverREST(t *testing.T) {
	a, _ := newAPIAs(t, operatorClaims)
	live, file := a.snapshot(t)
	conf := a.readGlobalJSON(t)
	section(t, conf, "auth")["enabled"] = false
	section(t, conf, "management")["allowPublicManagement"] = true

	code, body := a.putGlobalJSON(t, conf)
	if code != http.StatusForbidden {
		t.Fatalf("an operator switching authentication off got %d %s, want 403", code, body)
	}
	for _, field := range []string{"auth.enabled", "management.allow_public_management"} {
		if !strings.Contains(body, field) {
			t.Errorf("the refusal does not name %s: %s", field, body)
		}
	}
	a.requireUnchanged(t, "a refused operator save", live, file)
}

// TestOperatorBoundaryChangesAreRefusedOverREST covers the rest of the
// boundary the review named, each as the dashboard would send it: the whole
// object read back, one field edited.
func TestOperatorBoundaryChangesAreRefusedOverREST(t *testing.T) {
	cases := []struct {
		field  string
		mutate func(t *testing.T, conf map[string]any)
	}{
		{"auth.paseto_secret", func(t *testing.T, c map[string]any) {
			section(t, c, "auth")["pasetoSecret"] = "an-operator-chosen-session-key-of-32+"
		}},
		{"rbac.roles", func(t *testing.T, c map[string]any) {
			c["rbac"] = map[string]any{"enabled": true, "roles": []any{map[string]any{
				"role": "operator", "permissions": []any{map[string]any{"resource": "*", "action": "*"}}}}}
		}},
		{"audit.enabled", func(t *testing.T, c map[string]any) { section(t, c, "audit")["enabled"] = false }},
		{"management.allowed_ips", func(t *testing.T, c map[string]any) {
			section(t, c, "management")["allowedIps"] = []any{"0.0.0.0/0"}
		}},
		{"management.bind", func(t *testing.T, c map[string]any) { section(t, c, "management")["bind"] = "0.0.0.0" }},
		{"management.cors.allowed_origins", func(t *testing.T, c map[string]any) {
			section(t, c, "management")["cors"] = map[string]any{"allowedOrigins": []any{"https://evil.example"}, "allowCredentials": true}
		}},
		{"management.allow_public_management", func(t *testing.T, c map[string]any) {
			section(t, c, "management")["allowPublicManagement"] = true
		}},
		{"waf.trust_cloudflare_headers", func(t *testing.T, c map[string]any) {
			section(t, c, "waf")["trustCloudflareHeaders"] = true
		}},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			a, _ := newAPIAs(t, operatorClaims)
			live, file := a.snapshot(t)
			conf := a.readGlobalJSON(t)
			tc.mutate(t, conf)
			code, body := a.putGlobalJSON(t, conf)
			if code != http.StatusForbidden || !strings.Contains(body, tc.field) {
				t.Fatalf("an operator changing %s got %d %s, want 403 naming it", tc.field, code, body)
			}
			a.requireUnchanged(t, "a refused operator save", live, file)
		})
	}
}

// TestOperatorSavesTheWholeObjectWithAnOperationalChange is the dashboard's
// everyday save: the whole object read back -- every stored secret as the
// placeholder -- with one operational setting edited. It must succeed, and
// only that setting may change.
func TestOperatorSavesTheWholeObjectWithAnOperationalChange(t *testing.T) {
	a, _ := newAPIAs(t, operatorClaims)
	before, _ := a.snapshot(t)
	conf := a.readGlobalJSON(t)
	section(t, conf, "waf")["paranoiaLevel"] = 3

	if code, body := a.putGlobalJSON(t, conf); code != http.StatusOK {
		t.Fatalf("an operator's operational save got %d %s, want 200", code, body)
	}
	after, _ := a.snapshot(t)
	if after.GetWaf().GetParanoiaLevel() != 3 {
		t.Fatalf("the operational change was not stored: paranoia %d", after.GetWaf().GetParanoiaLevel())
	}
	if after.GetAuth().GetPasetoSecret() != before.GetAuth().GetPasetoSecret() ||
		after.GetAudit().GetSignatureKey() != before.GetAudit().GetSignatureKey() {
		t.Fatal("an operator's operational save changed a stored key")
	}
}

// TestOperatorCannotSwitchAuthenticationOffOverGRPC is the same refusal on
// the other transport the save is served over. (Connect does not serve
// UpdateGlobalConfig; it answers unimplemented.)
func TestOperatorCannotSwitchAuthenticationOffOverGRPC(t *testing.T) {
	a, _ := newAPIAs(t, operatorClaims)
	live, file := a.snapshot(t)
	resp, err := a.grpc.GetGlobalConfig(context.Background(), &gateonv1.GetGlobalConfigRequest{})
	if err != nil {
		t.Fatalf("gRPC GetGlobalConfig: %v", err)
	}
	conf := resp.GetConfig()
	conf.Auth.Enabled = false

	_, err = a.grpc.UpdateGlobalConfig(context.Background(), &gateonv1.UpdateGlobalConfigRequest{Config: conf})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(status.Convert(err).Message(), "auth.enabled") {
		t.Fatalf("an operator switching authentication off over gRPC got %v, want PermissionDenied naming auth.enabled", err)
	}
	a.requireUnchanged(t, "a refused gRPC save", live, file)

	// The same object with only an operational change goes through.
	conf.Auth.Enabled = true
	conf.Waf.ParanoiaLevel = 2
	if _, err := a.grpc.UpdateGlobalConfig(context.Background(), &gateonv1.UpdateGlobalConfigRequest{Config: conf}); err != nil {
		t.Fatalf("an operator's operational save over gRPC: %v", err)
	}
}

// TestAdministratorMayChangeTheBoundary: the rule restricts operators only.
func TestAdministratorMayChangeTheBoundary(t *testing.T) {
	a, _ := newAdminAPI(t)
	conf := a.readGlobalJSON(t)
	section(t, conf, "management")["allowedIps"] = []any{"192.0.2.0/24"}
	section(t, conf, "audit")["retentionDays"] = 30
	section(t, conf, "waf")["trustCloudflareHeaders"] = true
	if code, body := a.putGlobalJSON(t, conf); code != http.StatusOK {
		t.Fatalf("an administrator's boundary change got %d %s, want 200", code, body)
	}
	after, _ := a.snapshot(t)
	if got := after.GetManagement().GetAllowedIps(); len(got) != 1 || got[0] != "192.0.2.0/24" {
		t.Fatalf("the administrator's change was not stored: %v", got)
	}
}
