// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/auth"
)

func policyServing(t *testing.T, expr string, claims map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	mw, err := Policy(PolicyConfig{Rules: []PolicyRule{{Expression: expr}}})
	if err != nil {
		t.Fatalf("build policy %q: %v", expr, err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestPolicyReadsClaimsAsDocumented pins the shape the editor documents:
// auth is the verified token's claims themselves, so a claim is auth.role,
// not auth.claims.role -- which the help text used to say.
func TestPolicyReadsClaimsAsDocumented(t *testing.T) {
	const rule = `has(auth.role) && auth.role == "admin"`
	if code := policyServing(t, rule, map[string]any{"role": "admin"}).Code; code != http.StatusOK {
		t.Errorf("admin: status %d, want 200", code)
	}
	if code := policyServing(t, rule, map[string]any{"role": "viewer"}).Code; code != http.StatusForbidden {
		t.Errorf("viewer: status %d, want 403", code)
	}
}

// TestPolicyEvaluationErrorStaysOnTheServer: a rule that fails to evaluate
// answered 500 with the CEL error in the body, so any client could read the
// policy's structure -- which keys it reads and how -- off the error.
func TestPolicyEvaluationErrorStaysOnTheServer(t *testing.T) {
	rec := policyServing(t, `auth.claims.role == "admin"`, map[string]any{"role": "admin"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 for a rule that cannot be evaluated", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "claims") || strings.Contains(body, "no such key") {
		t.Errorf("the client was told why the policy failed: %s", body)
	}
}
