// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/stretchr/testify/assert"
)

func TestJA4PlusMitigationE2E(t *testing.T) {
	// Initialize telemetry store
	dbPath := filepath.Join(t.TempDir(), "ja4plus_e2e_test.db")
	_ = telemetry.InitPathStatsStore("sqlite:"+dbPath, 1)
	defer telemetry.ClosePathStatsStore(context.Background())

	// Define a backend
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	ja4 := "t13d1516h2_8c224e757c16_0d2e82e5b8e9"

	// Publish the JA4 the way the TLS listener does when gateon terminates TLS
	// itself: straight into the request state.
	//
	// This test used to set X-JA4-Fingerprint on each request instead. That
	// header is the fallback for an upstream terminator, and it is now only
	// honoured when the immediate peer is a trusted proxy — otherwise it is
	// just a string the client chose, and JA4+ is the reputation key.
	// httptest.NewRequest gives every request a RemoteAddr of 192.0.2.1, which
	// is not trusted, so the header was correctly ignored and the fingerprint
	// the middleware computed no longer matched the one the test mitigated:
	// the request sailed through with 200 where the test wanted 403.
	//
	// Setting rs.JA4 models the common deployment rather than the fallback, so
	// the test exercises JA4+ mitigation without depending on a header whose
	// trust rules are not what it is trying to prove.

	// seenJA4Plus is the composite the gateway actually derives for these
	// requests. The test mitigates that value rather than reassembling it as
	// ja4 + "_" + GenerateJA4H(req): the two are supposed to agree, but when
	// they silently disagreed this test failed with a 200 and no indication
	// which half was wrong. Reading it from the chain means the test asserts
	// the property it cares about — mitigating the fingerprint the gateway
	// computes blocks that client — and cannot drift from how the composite is
	// assembled.
	var seenJA4Plus string

	withJA4 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rs := request.GetRequestState(r); rs != nil {
				rs.JA4 = ja4
				// GetJA4Plus returns the cached composite as soon as it is set,
				// so clearing it is what makes the JA4 above take effect.
				rs.JA4Plus = ""
			}
			seenJA4Plus = telemetry.GetJA4Plus(r)
			next.ServeHTTP(w, r)
		})
	}

	// Wrap with middleware chain
	handler := middleware.Chain(
		middleware.WithRequestState("test-ep", "test", false),
		withJA4,
		middleware.UserMitigation(),
	)(middleware.ThreatRecognition("test-route")(backend))

	// 1. Initial request (Clean)
	req1 := httptest.NewRequest("GET", "/safe", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// 2. Malicious request (Trigger Mitigation)
	// We'll use a gambling keyword to trigger ThreatRecognition
	req2 := httptest.NewRequest("GET", "/search?q=online+casino", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code) // ThreatRecognition just detects by default

	// Manually trigger mitigation in telemetry for the fingerprint the gateway
	// derived for this client on the request just served.
	ja4plus := seenJA4Plus
	if ja4plus == "" || !strings.HasPrefix(ja4plus, ja4+"_") {
		t.Fatalf("gateway derived an unexpected JA4+ %q; want one starting %q_", ja4plus, ja4)
	}
	telemetry.MarkUserMitigated(ja4plus, "JA4+", "Malicious behavior detected", "gambling")

	// Wait for cache/DB update
	time.Sleep(100 * time.Millisecond)

	// 3. Subsequent request (Should be blocked by JA4+)
	req3 := httptest.NewRequest("GET", "/safe", nil)
	// Must have SAME headers to get same JA4H
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	assert.Equal(t, http.StatusForbidden, rec3.Code)
	assert.Contains(t, rec3.Body.String(), "Compromised Fingerprint")

	// 4. Remove mitigation
	telemetry.MarkUserUnmitigated(ja4plus)
	telemetry.ResetReputation(ja4plus)
	time.Sleep(2 * time.Second)

	// 5. Request after unmitigation (Should be allowed)
	req4 := httptest.NewRequest("GET", "/safe", nil)
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)
	assert.Equal(t, http.StatusOK, rec4.Code)
}
