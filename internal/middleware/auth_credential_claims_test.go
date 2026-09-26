// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The dashboard documents required_scopes, required_roles and map_claim_X as
// settings for every auth type. JWT, PASETO, OIDC and OAuth2 apply them. The
// apikey and basic types read them into their config and then never looked at
// them: a route requiring the "admin" role let every valid key through, and a
// mapped header -- the one a backend is told carries the verified tenant or
// user -- reached the backend exactly as the client wrote it.
//
// An API key yields its tenant and a basic-auth login its username, and those
// are the claims these credentials can offer. Neither carries a role or a
// scope, so a route that requires one refuses them, the same way a token
// missing the role is refused.

// buildAuth creates an auth middleware through the factory, as a route does.
func buildAuth(t *testing.T, cfg map[string]string) Middleware {
	t.Helper()
	mw, err := NewFactory(nil, nil, nil, nil, t.TempDir()).
		Create(&gateonv1.Middleware{Id: "auth-under-test", Type: "auth", Config: cfg}, "route-under-test")
	if err != nil {
		t.Fatalf("build auth middleware: %v", err)
	}
	return mw
}

// serveAuth sends req through mw and returns the status and the headers the
// backend received (nil when the backend was not reached).
func serveAuth(mw Middleware, req *http.Request) (int, http.Header) {
	var seen http.Header
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code, seen
}

func apiKeyRequest(key string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	req.Header.Set("X-API-Key", key)
	return req
}

func basicRequest(user, pass string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	req.SetBasicAuth(user, pass)
	return req
}

func TestCredentialAuthEnforcesRequiredRolesAndScopes(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]string
		req  func() *http.Request
	}{
		{"apikey requires role", map[string]string{"type": "apikey", "key_k-123": "tenant-a", "required_roles": "admin"},
			func() *http.Request { return apiKeyRequest("k-123") }},
		{"apikey requires scope", map[string]string{"type": "apikey", "key_k-123": "tenant-a", "required_scopes": "orders:write"},
			func() *http.Request { return apiKeyRequest("k-123") }},
		{"basic requires role", map[string]string{"type": "basic", "username": "alice", "password": "s3cret", "required_roles": "admin"},
			func() *http.Request { return basicRequest("alice", "s3cret") }},
		{"basic users requires scope", map[string]string{"type": "basic", "users": "alice:s3cret,bob:hunter2", "required_scopes": "orders:write"},
			func() *http.Request { return basicRequest("bob", "hunter2") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Control: the same credential is accepted when nothing more is
			// required of it, so a refusal below is about the requirement.
			open := make(map[string]string, len(tc.cfg))
			for k, v := range tc.cfg {
				if k != "required_roles" && k != "required_scopes" {
					open[k] = v
				}
			}
			if status, _ := serveAuth(buildAuth(t, open), tc.req()); status != http.StatusOK {
				t.Fatalf("control: valid credential without a requirement got %d, want 200", status)
			}

			status, seen := serveAuth(buildAuth(t, tc.cfg), tc.req())
			if status == http.StatusOK || seen != nil {
				t.Fatalf("a credential that carries no roles or scopes reached the backend (status %d) "+
					"on a route configured to require one; the requirement was never checked", status)
			}
		})
	}
}

func TestCredentialAuthSetsMappedHeadersFromTheCredentialOnly(t *testing.T) {
	cases := []struct {
		name, header, want string
		cfg                map[string]string
		req                func() *http.Request
	}{
		{name: "apikey tenant", header: "X-Tenant-Id", want: "tenant-a",
			cfg: map[string]string{"type": "apikey", "key_k-123": "tenant-a", "map_claim_tenant_id": "X-Tenant-Id"},
			req: func() *http.Request { return apiKeyRequest("k-123") }},
		{name: "basic user", header: "X-User-Id", want: "alice",
			cfg: map[string]string{"type": "basic", "username": "alice", "password": "s3cret", "map_claim_sub": "X-User-Id"},
			req: func() *http.Request { return basicRequest("alice", "s3cret") }},
		{name: "basic users", header: "X-User-Id", want: "bob",
			cfg: map[string]string{"type": "basic", "users": "alice:s3cret,bob:hunter2", "map_claim_sub": "X-User-Id"},
			req: func() *http.Request { return basicRequest("bob", "hunter2") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req()
			req.Header.Set(tc.header, "victim") // the client's own copy
			status, seen := serveAuth(buildAuth(t, tc.cfg), req)
			if status != http.StatusOK {
				t.Fatalf("valid credential got %d, want 200", status)
			}
			if got := seen.Get(tc.header); got != tc.want {
				t.Errorf("backend saw %s=%q, want %q from the verified credential: "+
					"the client's copy of a mapped header was forwarded as verified", tc.header, got, tc.want)
			}
		})
	}
}

// A preflight is let past authentication, because a browser will not send
// credentials on one. It must not carry the client's copies of the mapped
// headers past it either: those are only ever the gateway's to set. This is
// the rule forwardauth.go already states and follows for its own identity
// headers; the claim-mapping auth types did not.
func TestAuthPreflightDoesNotForwardClientMappedHeaders(t *testing.T) {
	for _, cfg := range []map[string]string{
		{"type": "jwt", "secret": "0123456789abcdef0123456789abcdef", "map_claim_tenant_id": "X-Tenant-Id"},
		{"type": "paseto", "secret": "0123456789abcdef0123456789abcdef", "map_claim_tenant_id": "X-Tenant-Id"},
		{"type": "oauth2", "introspection_url": "http://127.0.0.1:1/introspect", "client_id": "gw",
			"client_secret": "s", "map_claim_tenant_id": "X-Tenant-Id"},
		{"type": "apikey", "key_k-123": "tenant-a", "map_claim_tenant_id": "X-Tenant-Id"},
		{"type": "basic", "username": "alice", "password": "s3cret", "map_claim_tenant_id": "X-Tenant-Id"},
		{"type": "basic", "users": "alice:s3cret", "map_claim_tenant_id": "X-Tenant-Id"},
	} {
		t.Run(cfg["type"], func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, "/orders", nil)
			req.Header.Set("Origin", "https://app.example.com")
			req.Header.Set("Access-Control-Request-Method", http.MethodPost)
			req.Header.Set("X-Tenant-Id", "victim")
			status, seen := serveAuth(buildAuth(t, cfg), req)
			if seen == nil {
				t.Fatalf("control: preflight was not passed through (status %d)", status)
			}
			if got := seen.Get("X-Tenant-Id"); got != "" {
				t.Errorf("preflight forwarded the client's X-Tenant-Id=%q unverified", got)
			}
		})
	}
}
