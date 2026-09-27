// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// managementAPI answers GET /v1/routes/stats for the Bearer token "secret"
// only, as the management API does with authentication on.
func managementAPI(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/v1/routes/stats" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{
			"busy":  [{"requestCount":3,"errorCount":1,"avgLatencyUs":2000,"activeConn":1},
			          {"requestCount":1,"errorCount":0,"avgLatencyUs":6000,"activeConn":2}],
			"quiet": []
		}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestTopSendsItsToken: `gateon top` fetched the management API with no
// credentials, so with authentication on -- every real deployment -- each poll
// was refused. It sends the token it is given as a Bearer credential.
func TestTopSendsItsToken(t *testing.T) {
	srv := managementAPI(t)
	stats, err := fetchStats(t.Context(), srv.Client(), srv.URL, "secret")
	if err != nil {
		t.Fatalf("fetchStats: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("routes: %d, want 2", len(stats))
	}
	busy := stats[0]
	if busy.ID != "busy" || busy.Requests != 4 || busy.Errors != 1 || busy.ActiveConn != 3 || busy.Latency != 3 {
		t.Errorf("busy = %+v, want 4 requests, 1 error, 3 connections and 3 ms (weighted by requests)", busy)
	}
}

// TestTopSaysWhyWithoutAToken: a refusal names what to do about it, and stops
// the loop rather than repeating it every two seconds.
func TestTopSaysWhyWithoutAToken(t *testing.T) {
	srv := managementAPI(t)
	for _, token := range []string{"", "wrong"} {
		if _, err := fetchStats(t.Context(), srv.Client(), srv.URL, token); !errors.Is(err, errUnauthorized) {
			t.Errorf("token %q: err = %v, want errUnauthorized", token, err)
		}
	}
}

// TestTopArgsReadTheTokenFromTheFlagOrTheEnvironment pins how the token is
// given: --token, --token=, or GATEON_TOKEN when neither is.
func TestTopArgsReadTheTokenFromTheFlagOrTheEnvironment(t *testing.T) {
	t.Setenv(TokenEnv, "from-env")
	for _, tc := range []struct {
		args            []string
		wantURL, wantTk string
	}{
		{nil, "http://localhost:8080", "from-env"},
		{[]string{"http://gw:9000"}, "http://gw:9000", "from-env"},
		{[]string{"http://gw:9000", "--token", "from-flag"}, "http://gw:9000", "from-flag"},
		{[]string{"--token=from-flag", "http://gw:9000"}, "http://gw:9000", "from-flag"},
	} {
		url, token := TopArgs(tc.args, "http://localhost:8080")
		if url != tc.wantURL || token != tc.wantTk {
			t.Errorf("TopArgs(%q) = %q, %q; want %q, %q", tc.args, url, token, tc.wantURL, tc.wantTk)
		}
	}
}
