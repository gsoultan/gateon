// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// TestPowIsNotDisabledByARequestPath closes an exemption the client chose.
//
// The skip used to be kind.IsInternalPath(r.URL.Path), which matches gateon's
// own management paths by prefix -- /v1/routes, /v1/global, /v1/security. On a
// proxy route those are not gateon's paths, they are the upstream's, so on a
// catch-all route a client turned the challenge off by prefixing their path.
func TestPowIsNotDisabledByARequestPath(t *testing.T) {
	var reached bool
	h := Pow(1, powTestThreshold, "test-secret", "pow-path-test")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))

	// A path that IsInternalPath matches by prefix, on an ordinary route.
	r := httptest.NewRequest(http.MethodGet, "http://x/v1/global/anything", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	// powTestThreshold sits above the neutral score, so an unknown client is
	// challenged -- the same device the other PoW tests use.

	h.ServeHTTP(httptest.NewRecorder(), r)

	if reached {
		t.Error("a low-reputation client skipped the proof-of-work challenge by " +
			"prefixing its path with one of gateon's management routes")
	}
}

// TestPowStillSkipsManagementTraffic keeps the real exemption working. The
// management plane is identified by which listener accepted the connection,
// which a request cannot claim for itself.
func TestPowStillSkipsManagementTraffic(t *testing.T) {
	var reached bool
	h := Pow(1, powTestThreshold, "test-secret", "pow-mgmt-test")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))

	r := httptest.NewRequest(http.MethodGet, "http://x/v1/global", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r = r.WithContext(request.WithState(r.Context(),
		&request.RequestState{IsManagement: true}))

	h.ServeHTTP(httptest.NewRecorder(), r)

	if !reached {
		t.Error("management traffic was challenged; the dashboard cannot solve " +
			"a proof of work")
	}
}
