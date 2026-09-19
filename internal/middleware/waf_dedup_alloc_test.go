// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// discardWriter is a ResponseWriter that does nothing, so the only allocations
// measured are the middleware's own.
type discardWriter struct{ h http.Header }

func (d *discardWriter) Header() http.Header         { return d.h }
func (d *discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardWriter) WriteHeader(int)             {}

// TestWAFDedupPathAllocatesNothing: the middleware hashed its whole
// configuration on every request — a sha256 over a dozen fmt.Fprintf calls —
// to produce the fingerprint the per-request deduplication compares against.
// The configuration cannot change after the middleware is built, so that hash is
// a per-request cost for a route-constant value. Once a request has already been
// through an identical policy, the second pass should be a slice scan and
// nothing else.
func TestWAFDedupPathAllocatesNothing(t *testing.T) {
	mw, err := WAF(WAFConfig{ParanoiaLevel: 1})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	rs := &request.RequestState{}
	req := withState(httptest.NewRequest(http.MethodGet, "/", nil), rs)
	w := &discardWriter{h: http.Header{}}

	// First pass records the policy fingerprint on the request state.
	handler.ServeHTTP(w, req)
	if len(rs.ExecutedWAFs) != 1 {
		t.Fatalf("expected one executed WAF fingerprint, got %d", len(rs.ExecutedWAFs))
	}

	// Every later pass with the same policy is the dedup path.
	allocs := testing.AllocsPerRun(50, func() { handler.ServeHTTP(w, req) })
	if allocs != 0 {
		t.Fatalf("dedup path allocates %.0f times per request; the config fingerprint is being recomputed per request", allocs)
	}
}
