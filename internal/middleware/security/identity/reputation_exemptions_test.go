// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// scoredRequest is a request from ip carrying fingerprint fp whose identity
// holds exactly score, and the identity it resolves to.
func scoredRequest(t *testing.T, fp, ip string, score float64, mgmt bool) *http.Request {
	t.Helper()
	key := repid.For(fp, ip)
	// A peer's value, so the score is exactly what the test names rather than
	// what the adaptive penalty makes of a series of violations.
	telemetry.ApplyRemoteReputation(key, score, 1, []string{"waf_blocked"})
	t.Cleanup(func() { telemetry.ResetReputation(key) })

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.RemoteAddr = ip + ":41500"
	rs := &request.RequestState{JA4Plus: fp, IsManagement: mgmt}
	return req.WithContext(request.WithState(req.Context(), rs))
}

func blockerAnswer(h http.Handler, req *http.Request) int {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// TestTheBlockerRefusesOnlyBelowItsThreshold pins the boundary the blocker is
// documented at: below 2.0 is refused, anything at or above it is served. A
// threshold that crept upwards would refuse clients that are merely degraded
// -- a penalty meant to tighten the WAF and proof-of-work turned into a 403 on
// every route -- and no test drew the line.
func TestTheBlockerRefusesOnlyBelowItsThreshold(t *testing.T) {
	h := blockerHandler(t)
	const fp = "t13d1516h2_threshold_boundary"
	for _, tc := range []struct {
		ip    string
		score float64
		want  int
	}{
		{"203.0.113.201", 1.5, http.StatusForbidden},
		{"198.51.100.202", 2.0, http.StatusOK},
		{"192.0.2.203", 59, http.StatusOK},
	} {
		if got := blockerAnswer(h, scoredRequest(t, fp, tc.ip, tc.score, false)); got != tc.want {
			t.Errorf("a client scoring %v got %d, want %d", tc.score, got, tc.want)
		}
	}
}

// TestTheBlockerExemptsLoopbackAndManagementTraffic pins the two exemptions the
// blocker states. The loopback one is the guard ADR 0011 found dead -- it
// compared the fingerprint to "127.0.0.1" -- and fixed to compare the resolved
// address, with nothing to stop it dying again.
func TestTheBlockerExemptsLoopbackAndManagementTraffic(t *testing.T) {
	h := blockerHandler(t)
	const fp = "t13d1516h2_exemptions"
	if got := blockerAnswer(h, scoredRequest(t, fp, "127.0.0.1", 0, false)); got != http.StatusOK {
		t.Errorf("a loopback client with a score of zero got %d, want 200", got)
	}
	if got := blockerAnswer(h, scoredRequest(t, fp, "203.0.113.204", 0, true)); got != http.StatusOK {
		t.Errorf("management traffic from a client with a score of zero got %d, want 200", got)
	}
	if got := blockerAnswer(h, scoredRequest(t, fp, "203.0.113.205", 0, false)); got != http.StatusForbidden {
		t.Errorf("control: an ordinary client with a score of zero got %d, want 403", got)
	}
}
