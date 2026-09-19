// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A mapped claim header (map_claim_tenant_id=X-Tenant-Id) tells the backend
// "this value came from the verified token". MapClaimsToHeaders only Set the
// header when the claim was present, so a token without the claim let the
// client's own X-Tenant-Id through untouched -- and DryRun, which continues on
// failure, forwarded every mapped header exactly as the client sent it.

func claimMappingConfig() AuthBaseConfig {
	return AuthBaseConfig{ClaimMappings: map[string]string{
		"sub":       "X-User-Id",
		"tenant_id": "X-Tenant-Id",
	}}
}

// serveWithClaimHeaders runs one request carrying token and the client's own
// copies of the mapped headers, and returns what the backend saw.
func serveWithClaimHeaders(t *testing.T, cfg AuthBaseConfig, token string, client map[string]string) (*httptest.ResponseRecorder, http.Header) {
	t.Helper()
	v, err := NewJWTValidator(JWTConfig{AuthBaseConfig: cfg, Secret: []byte(testSecret)})
	if err != nil {
		t.Fatalf("build validator: %v", err)
	}
	var seen http.Header
	h := v.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, val := range client {
		req.Header.Set(k, val)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr, seen
}

func TestMappedClaimHeaderIsStrippedWhenTheTokenLacksTheClaim(t *testing.T) {
	rr, seen := serveWithClaimHeaders(t, claimMappingConfig(), mint(t, baseClaims()),
		map[string]string{"X-Tenant-Id": "victim-tenant", "X-User-Id": "victim"})
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
	if got := seen.Get("X-User-Id"); got != "user-1" {
		t.Errorf("X-User-Id = %q, want the token's sub %q", got, "user-1")
	}
	if got := seen.Get("X-Tenant-Id"); got != "" {
		t.Errorf("backend saw X-Tenant-Id=%q from the client; the token carries no tenant_id", got)
	}
}

func TestDryRunDoesNotForwardClientSuppliedClaimHeaders(t *testing.T) {
	cfg := claimMappingConfig()
	cfg.DryRun = true
	rr, seen := serveWithClaimHeaders(t, cfg, "", map[string]string{"X-User-Id": "admin"})
	if rr.Code != http.StatusOK {
		t.Fatalf("dry run must continue to the backend, got %d", rr.Code)
	}
	if got := seen.Get("X-User-Id"); got != "" {
		t.Errorf("dry run forwarded the client's X-User-Id=%q as if a token had set it", got)
	}
}
