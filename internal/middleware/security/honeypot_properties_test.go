// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
)

// honeypotAnswer sends a GET for path from ip through h.
func honeypotAnswer(h http.Handler, ip, path string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = ip + ":42500"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// bothHoneypots is the global honeypot every entrypoint carries and the
// per-route honeypot middleware, each over a backend that answers 200. They
// keep separate copies of the ban check, so each needs its own proof.
func bothHoneypots(t *testing.T) map[string]http.Handler {
	t.Helper()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	globals := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	return map[string]http.Handler{
		"global":    HoneypotGlobal(globals)(ok),
		"per-route": Honeypot(HoneypotConfig{Paths: defaultHoneypotPaths()})(ok),
	}
}

// TestAHoneypotBanEnds pins the escalation ladder's other half: a ban lasts as
// long as its rung and then lifts. A check that ignored the expiry would make
// every trap hit permanent until a restart, and nothing tested that it does
// not.
func TestAHoneypotBanEnds(t *testing.T) {
	for name, h := range bothHoneypots(t) {
		t.Run(name, func(t *testing.T) {
			resetHoneypotState(t)
			const ip = "198.51.100.211"
			blockHoneypotIP(ip, time.Now().Add(time.Hour))
			if got := honeypotAnswer(h, ip, "/"); got != http.StatusForbidden {
				t.Fatalf("setup: a banned address got %d", got)
			}
			blockHoneypotIP(ip, time.Now().Add(-time.Second))
			if got := honeypotAnswer(h, ip, "/"); got != http.StatusOK {
				t.Fatalf("an address whose ban has run out still gets %d", got)
			}
		})
	}
}

// TestATrapCoversEverythingUnderIt pins "a trap matches exactly, or as a
// directory prefix": /.git/config is the request a scanner actually sends for
// the /.git trap, and exact matching alone would let it straight through.
func TestATrapCoversEverythingUnderIt(t *testing.T) {
	for name, h := range bothHoneypots(t) {
		t.Run(name, func(t *testing.T) {
			resetHoneypotState(t)
			const ip = "198.51.100.212"
			if got := honeypotAnswer(h, ip, "/.git/config"); got != http.StatusForbidden {
				t.Fatalf("a request for /.git/config got %d; the /.git trap does not cover it", got)
			}
			if got := honeypotAnswer(h, "198.51.100.213", "/.github-pages/index.html"); got != http.StatusOK {
				t.Fatalf("control: /.github-pages is not under /.git and got %d", got)
			}
		})
	}
}

// TestAFullStrikeMapBansAtTheTop pins the at-capacity rule: once the strike
// map is full, a new address is banned at the top of the ladder, not the
// bottom -- under a scan big enough to fill it, starting every newcomer at
// fifteen minutes is how the trap stops working when it is needed most.
func TestAFullStrikeMapBansAtTheTop(t *testing.T) {
	resetHoneypotState(t)
	now := time.Now()
	for i := range maxHoneypotBlocklist {
		honeypotBanFor(netAddrForIndex(i), now)
	}
	top := honeypotBanLadder[len(honeypotBanLadder)-1]
	if got := honeypotBanFor("203.0.113.214", now); got != top {
		t.Fatalf("with the strike map full a new address was banned for %s, want %s", got, top)
	}
}
