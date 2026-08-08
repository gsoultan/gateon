// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// resetHoneypotBlocklist clears the package-level blocklist so these tests do
// not inherit or leak bans. The map is process-wide by design — that is exactly
// the property under test — so it has to be reset explicitly.
func resetHoneypotBlocklist(t *testing.T) {
	t.Helper()
	blocklistMu.Lock()
	clear(honeypotBlocklist)
	blocklistMu.Unlock()
	t.Cleanup(func() {
		blocklistMu.Lock()
		clear(honeypotBlocklist)
		blocklistMu.Unlock()
	})
}

// TestHoneypotDoesNotBanLoopback is the regression test for a self-inflicted
// outage.
//
// Tripping a trap path recorded a 24-hour ban against the caller's IP, in a
// process-wide in-memory map with no way to clear it short of a restart. Every
// local caller shares 127.0.0.1, so anything local touching a trap path — a
// health check, a scanner, an administrator following a stale link — locked the
// dashboard and the management API out for the rest of the day.
//
// It also made the e2e suite unreadable: Playwright drives everything from
// loopback, so the honeypot test banned the address every later test used and
// they failed with 403 where they expected 200.
func TestHoneypotDoesNotBanLoopback(t *testing.T) {
	resetHoneypotBlocklist(t)

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	h := Honeypot(HoneypotConfig{Paths: []string{"/secret-admin"}})(backend)

	// Trip the trap from loopback.
	trap := httptest.NewRequest(http.MethodGet, "/secret-admin", nil)
	trap.RemoteAddr = "127.0.0.1:5555"
	trapRec := httptest.NewRecorder()
	h.ServeHTTP(trapRec, trap)

	// The trap itself must still refuse the request.
	if trapRec.Code != http.StatusForbidden {
		t.Errorf("trap path returned %d, want 403 — the honeypot must still refuse it",
			trapRec.Code)
	}

	// A later, unrelated request from the same loopback address must not be
	// caught by a lingering ban.
	next := httptest.NewRequest(http.MethodGet, "/perfectly-normal", nil)
	next.RemoteAddr = "127.0.0.1:5556"
	nextRec := httptest.NewRecorder()
	h.ServeHTTP(nextRec, next)

	if nextRec.Code != http.StatusOK {
		t.Errorf("loopback was banned by the honeypot: later request got %d, want 200",
			nextRec.Code)
	}
}

// TestHoneypotStillBansRemoteClients is the other half: the loopback exemption
// must not turn the honeypot off for the callers it exists to catch.
func TestHoneypotStillBansRemoteClients(t *testing.T) {
	resetHoneypotBlocklist(t)

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Honeypot(HoneypotConfig{Paths: []string{"/secret-admin"}})(backend)

	trap := httptest.NewRequest(http.MethodGet, "/secret-admin", nil)
	trap.RemoteAddr = "203.0.113.44:5555"
	h.ServeHTTP(httptest.NewRecorder(), trap)

	next := httptest.NewRequest(http.MethodGet, "/perfectly-normal", nil)
	next.RemoteAddr = "203.0.113.44:5556"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, next)

	if rec.Code != http.StatusForbidden {
		t.Errorf("remote client that tripped the trap got %d on its next request, want 403",
			rec.Code)
	}
}

// TestBlockHoneypotIPIgnoresLoopbackForms covers the address spellings a local
// caller can arrive as, so the exemption is not defeated by IPv6 or a port.
func TestBlockHoneypotIPIgnoresLoopbackForms(t *testing.T) {
	resetHoneypotBlocklist(t)

	for _, ip := range []string{"127.0.0.1", "::1", "127.0.0.53", "localhost"} {
		blockHoneypotIP(ip, time.Now().Add(time.Hour))
	}

	blocklistMu.RLock()
	n := len(honeypotBlocklist)
	blocklistMu.RUnlock()

	if n != 0 {
		t.Errorf("loopback forms were banned: blocklist has %d entries, want 0", n)
	}
}
