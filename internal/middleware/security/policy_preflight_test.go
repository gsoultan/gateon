// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPolicyAppliesToAPreflight: a CEL policy is an operator's deny decision,
// so a caller must not be able to step out of it by naming a preflight.
//
// One middleware, one rule, two paths: the rule discriminates, so this cannot
// pass by the policy denying (or allowing) everything.
func TestPolicyAppliesToAPreflight(t *testing.T) {
	mw, err := Policy(PolicyConfig{Rules: []PolicyRule{{
		Expression: `request.path != "/admin"`,
		Message:    "admin is closed",
	}}})
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}

	newPreflight := func(path string) *http.Request {
		r := httptest.NewRequest(http.MethodOptions, path, nil)
		r.Header.Set("Origin", "https://evil.example")
		r.Header.Set("Access-Control-Request-Method", "GET")
		return r
	}

	t.Run("denied path", func(t *testing.T) {
		var reached bool
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newPreflight("/admin"))

		if reached {
			t.Error("a preflight reached a path the policy denies; the rule is " +
				"opt-out by writing an Origin and an Access-Control-Request-Method")
		}
		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
		}
	})

	t.Run("allowed path", func(t *testing.T) {
		var reached bool
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newPreflight("/public"))

		if !reached {
			t.Errorf("a preflight to a permitted path was refused with %d; the "+
				"fix must only affect requests the policy was already denying", rr.Code)
		}
	})
}
