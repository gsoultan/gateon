// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding

package security

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// OPEN FINDING -- needs a design decision, see the reviewer report.
//
// TestOneIPv6CustomerCannotSwitchTheHoneypotOff: bans and strikes are keyed by
// the exact address, and an IPv6 customer is delegated a /64 -- 2^64 addresses
// it can source from at no cost. Rotating through them, a scanner is never
// refused for longer than the one request that tripped each ban, never climbs
// the ladder, and after ten thousand trap hits has filled both maps to their
// cap. At the cap the blocklist refuses to grow, so the next scanner to hit a
// trap -- anyone, on any address -- is not banned at all until entries expire,
// and the rotating customer can keep it that way.
//
// Keying IPv6 bans on the /64, as ADR 0011 does for reputation, is the obvious
// fix, but it widens whom one ban covers and so moves a trust boundary
// (arch <-> sec).
func TestOneIPv6CustomerCannotSwitchTheHoneypotOff(t *testing.T) {
	resetHoneypotState(t)
	now := time.Now()

	// Ten thousand trap hits from one /64, recorded exactly as the middleware
	// records one (the logging it also does is left out: it is 10,000 lines).
	for i := range maxHoneypotBlocklist {
		addr := fmt.Sprintf("2001:db8:1:2::%x", i+1)
		blockHoneypotIP(addr, now.Add(honeypotBanFor(addr, now)))
	}

	const scanner = "203.0.113.250"
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := Honeypot(HoneypotConfig{Paths: defaultHoneypotPaths()})(ok)
	serve := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = scanner + ":52000"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if got := serve("/.env"); got != http.StatusForbidden {
		t.Fatalf("setup: the trap itself answered %d", got)
	}
	if got := serve("/"); got != http.StatusForbidden {
		t.Fatalf("a scanner that hit a trap is not banned (got %d): one IPv6 customer "+
			"rotating inside its own /64 filled the ban list and switched bans off for everyone", got)
	}
}
