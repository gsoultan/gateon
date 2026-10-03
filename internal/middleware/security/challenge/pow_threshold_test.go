// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// penalisedRequest is a request from peer whose reputation has been lowered
// by penalty, so its threat score is penalty. The score is reset afterwards.
// A score belongs to a /24 (ADR 0024), so each case uses its own.
func penalisedRequest(t *testing.T, peer string, penalty float64) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.RemoteAddr = peer + ":4444"
	req.Header.Set("User-Agent", "pow-threshold-test")
	id := telemetry.GetReputationID(req)
	if penalty > 0 {
		telemetry.DecreaseReputation(id, penalty, "test: pow threshold")
	}
	t.Cleanup(func() { telemetry.ResetReputation(id) })
	if got := 100 - telemetry.GetReputationScore(id); got != penalty {
		t.Fatalf("threat score %v, want %v; the rest of this test would prove nothing", got, penalty)
	}
	// A fresh request, so nothing cached on the first one's state is reused.
	fresh := httptest.NewRequest(http.MethodGet, "/protected", nil)
	fresh.RemoteAddr = req.RemoteAddr
	fresh.Header.Set("User-Agent", req.UserAgent())
	return fresh
}

func challenged(threshold float64, req *http.Request) bool {
	reached := false
	Pow(1, threshold, "test-secret", "pow-threshold")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
	})).ServeHTTP(httptest.NewRecorder(), req)
	return !reached
}

// TestPowThresholdIsAThreatScore is T10. The setting reads "Serve challenge
// when IP threat score exceeds this (recommended 5)", and the middleware
// challenged when the *reputation* was below it: at 5, a client had to fall
// under a reputation of 5, which the reputation blocker refuses first and
// which penalties of 50 step over, so nobody was ever challenged. The
// direction is pinned both ways: a threat above the threshold is challenged,
// one below it is not.
func TestPowThresholdIsAThreatScore(t *testing.T) {
	cases := []struct {
		name      string
		peer      string
		penalty   float64
		threshold float64
		want      bool
	}{
		{"threat 50 exceeds the recommended 5", "100.64.71.1", 50, 5, true},
		{"threat 50 does not exceed 60", "100.64.72.1", 50, 60, false},
		{"a clean client has threat 0", "100.64.73.1", 0, 5, false},
		{"threshold 0 spares a clean client", "100.64.74.1", 0, 0, false},
		{"threshold 0 challenges any penalty", "100.64.75.1", 10, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := challenged(tc.threshold, penalisedRequest(t, tc.peer, tc.penalty)); got != tc.want {
				t.Errorf("threat %v at threshold %v: challenged=%v, want %v", tc.penalty, tc.threshold, got, tc.want)
			}
		})
	}
}

// TestPowPassAdmitsTheReloadAfterASolution: a solution used to be honoured
// only on the request that carried it, so the browser page -- which solves,
// then reloads -- was challenged again on the reload, for as long as the tab
// stayed open. That loop was invisible while T10 kept proof-of-work from
// firing; fixing the threshold made it live, so the two ship together.
func TestPowPassAdmitsTheReloadAfterASolution(t *testing.T) {
	h := newPowHandler("s3cret")
	id := issueChallenge(t, h)
	nonce, sol := solvePoW(t, id, 1)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, powRequest(id, nonce, sol))
	var pass *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == PowPassCookieName {
			pass = c
		}
	}
	if rec.Code != http.StatusOK || pass == nil {
		t.Fatalf("a correct solution: status %d, pass %v; want 200 and a pass cookie", rec.Code, pass)
	}

	reload := powRequest("", "", "")
	reload.AddCookie(pass)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reload)
	if rec.Code != http.StatusOK {
		t.Fatalf("the reload after a solution was challenged again (%d): the page would loop for ever", rec.Code)
	}

	elsewhere := powRequest("", "", "")
	elsewhere.RemoteAddr = "198.51.100.7:5555"
	elsewhere.AddCookie(pass)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, elsewhere)
	if rec.Code == http.StatusOK {
		t.Fatal("a proof-of-work pass issued to 203.0.113.9 was accepted from 198.51.100.7")
	}
}
