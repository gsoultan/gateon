// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The anomaly detector's brute-force check (opt-in) counted every 401 and 403
// an address received as a failed login, and above an 80% failure rate it
// shunned the address. A dashboard tab left open after its session expired
// polls, and every poll is a GET answered 401: with brute-force detection on,
// the tab's address was shunned within a check interval. So was a scanner the
// WAF refused. The per-IP detector was fixed for the same mistake in d29c7d27;
// this is its rule, on the request path the detector reads: a credential
// attempt is a POST, or a request whose Authorization carried a password
// (Basic, Digest). ADR 0029.

// answered records n requests from ip, each answered status, as the Metrics
// middleware hands a finished request to the aggregator.
func answered(agg *LocalMetricsAggregator, ip string, n int, status int, req *http.Request) {
	for range n {
		agg.RecordRequest(ip, status, req)
	}
}

// bruteForceDetector is the detector with only brute-force detection on, at
// the default sensitivity, reading agg.
func bruteForceDetector(agg *LocalMetricsAggregator) *AnomalyDetector {
	return &AnomalyDetector{
		config: &gateonv1.AnomalyDetectionConfig{
			Enabled: true, Sensitivity: 0.5, EnableBruteForceDetection: true,
		},
		aggregator: agg,
	}
}

// bruteForceOutcome runs one detection pass and reports whether a brute force
// was recorded against ip and whether ip ended up shunned.
func bruteForceOutcome(t *testing.T, agg *LocalMetricsAggregator, ip string) (recorded, shunned bool) {
	t.Helper()
	t.Cleanup(func() { _ = MarkIPUnmitigated(ip) })
	bruteForceDetector(agg).runChecks(t.Context(), time.Now())
	return threatRecorded(t, typeBruteForce, ip), IsIPMitigated(ip)
}

func TestAnExpiredSessionPollerIsNeitherThrottledNorShunned(t *testing.T) {
	initAnomalyTestStore(t)
	for _, tc := range []struct{ name, ip, authorization string }{
		{"session cookie", "198.51.100.70", ""},
		{"expired bearer token", "198.51.100.71", "Bearer eyJhbGciOiJFZERTQSJ9.expired"},
	} {
		agg := newIsolatedAggregator()
		poll := httptest.NewRequest(http.MethodGet, "/v1/metrics/snapshot", nil)
		poll.Header.Set("Cookie", "gateon_session=expired")
		if tc.authorization != "" {
			poll.Header.Set("Authorization", tc.authorization)
		}
		answered(agg, tc.ip, 24, http.StatusUnauthorized, poll) // four polls a minute for six minutes

		if recorded, shunned := bruteForceOutcome(t, agg, tc.ip); recorded || shunned {
			t.Errorf("%s: a tab polling with an expired session -- every request a GET answered 401 -- "+
				"was reported as brute force (%v) or shunned (%v)", tc.name, recorded, shunned)
		}
	}
}

// A login form may refuse bad credentials with 401 or with 403.
func TestCredentialStuffingIsStillShunned(t *testing.T) {
	initAnomalyTestStore(t)
	for _, tc := range []struct {
		ip     string
		status int
	}{
		{"198.51.100.72", http.StatusUnauthorized},
		{"198.51.100.75", http.StatusForbidden},
	} {
		agg := newIsolatedAggregator()
		answered(agg, tc.ip, 20, tc.status, httptest.NewRequest(http.MethodPost, "/login", nil))

		if recorded, shunned := bruteForceOutcome(t, agg, tc.ip); !recorded || !shunned {
			t.Errorf("20 logins POSTed and refused %d: brute force recorded = %v, shunned = %v; want both",
				tc.status, recorded, shunned)
		}
	}
}

func TestBasicAuthGuessingOverGetIsStillShunned(t *testing.T) {
	initAnomalyTestStore(t)
	const ip = "198.51.100.73"
	agg := newIsolatedAggregator()
	guess := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	guess.SetBasicAuth("admin", "guess")
	answered(agg, ip, 20, http.StatusUnauthorized, guess)

	if recorded, shunned := bruteForceOutcome(t, agg, ip); !recorded || !shunned {
		t.Errorf("20 Basic-auth guesses over GET refused: brute force recorded = %v, shunned = %v; want both",
			recorded, shunned)
	}
}

// A scanner's requests the WAF refused are exploit scanning, which the detector
// reads from its WAF-block count; they are not guesses at a credential.
func TestAScannersWAFRefusalsAreNotBruteForce(t *testing.T) {
	initAnomalyTestStore(t)
	const ip = "198.51.100.74"
	agg := newIsolatedAggregator()
	probe := httptest.NewRequest(http.MethodGet, "/.env", nil)
	for range 30 {
		agg.RecordWAFBlock(ip)
		agg.RecordRequest(ip, http.StatusForbidden, probe)
	}

	if recorded, shunned := bruteForceOutcome(t, agg, ip); recorded || shunned {
		t.Errorf("30 scanner probes the WAF refused 403 were reported as brute force (%v) or shunned by it (%v)",
			recorded, shunned)
	}
}
