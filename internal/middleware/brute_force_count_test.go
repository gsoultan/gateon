// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// The anomaly detector's brute-force check reads, per address, the refused
// credential attempts the Metrics middleware hands the aggregator. Whether a
// refusal was an attempt is read from the request itself (ADR 0029), so the
// middleware has to pass it: without it no refusal is an attempt, and brute
// force is never reported at all.
func TestMetricsCountsRefusedLoginsAndNotRefusedPolls(t *testing.T) {
	refuse := Metrics("brute-force-count")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	for _, tc := range []struct {
		name, method, ip string
		want             float64
	}{
		{"login", http.MethodPost, "198.51.100.180", 1},
		{"expired-session poll", http.MethodGet, "198.51.100.181", 0},
	} {
		req := httptest.NewRequest(tc.method, "/login", nil)
		req.RemoteAddr = tc.ip + ":51000"
		before := refusedAttempts(tc.ip) // the aggregator is the process's own
		refuse.ServeHTTP(httptest.NewRecorder(), req)

		if got := refusedAttempts(tc.ip) - before; got != tc.want {
			t.Errorf("%s refused 401: %v refused credential attempts counted for %s, want %v",
				tc.name, got, tc.ip, tc.want)
		}
	}
}

// refusedAttempts is what the brute-force check reads for ip.
func refusedAttempts(ip string) float64 {
	for _, s := range telemetry.GetAggregator().GetIPStats(0) {
		if s.IP == ip {
			return s.AuthFail
		}
	}
	return 0
}
