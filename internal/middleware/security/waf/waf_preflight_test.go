// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// TestWAF_PreflightDoesNotSkipInspection: the WAF's own comment called this
// branch a "CORS Preflight bypass", and it was exactly that. IsCorsPreflight
// reads three values the client writes, so any client could skip the engine,
// the entropy checks and response inspection by adding two headers to an
// OPTIONS request -- which may carry a query string and a body like any other.
//
// This is the same shape as the git Content-Type skip beside it in
// waf_bypass_test.go: a claim by the caller, trusted as a fact about the
// caller.
func TestWAF_PreflightDoesNotSkipInspection(t *testing.T) {
	mw, err := WAF(WAFConfig{ParanoiaLevel: 1})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	handler := mw(okOrigin())

	req := httptest.NewRequest(http.MethodOptions, sqliQuery, nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", "GET")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, withState(req, &request.RequestState{}))

	if rr.Code == http.StatusOK {
		t.Errorf("an SQLi carried on a preflight-shaped OPTIONS reached the "+
			"origin with %d; the whole WAF was opt-out by two headers", rr.Code)
	}
}

// TestWAF_BenignPreflightStillPasses keeps the fix from turning every browser
// preflight into a refusal: OPTIONS is in defaultAllowedMethods, and a
// preflight carrying nothing hostile must still be inspected and forwarded.
func TestWAF_BenignPreflightStillPasses(t *testing.T) {
	mw, err := WAF(WAFConfig{ParanoiaLevel: 1})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	handler := mw(okOrigin())

	req := httptest.NewRequest(http.MethodOptions, "/api/items", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Method", "POST")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, withState(req, &request.RequestState{}))

	if rr.Code != http.StatusOK {
		t.Errorf("a benign preflight was refused with %d; inspecting preflights "+
			"must not mean blocking them", rr.Code)
	}
}
