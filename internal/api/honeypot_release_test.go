// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware/security"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// honeypotGate is the trap every HTTP entrypoint carries, in front of a backend
// that answers 200, over a stock global configuration: deception off, so the
// built-in trap paths apply.
func honeypotGate(t *testing.T) http.Handler {
	t.Helper()
	globals := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return security.HoneypotGlobal(globals)(ok)
}

// serveFrom sends a GET for path from ip, with no forwarding headers.
func serveFrom(h http.Handler, ip, path string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = ip + ":42000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// TestReleasingAnAddressLiftsItsHoneypotBan is the regression test for a
// release that reported success and left the address banned.
//
// A trap hit bans the address in the honeypot's own in-memory blocklist, which
// every HTTP entrypoint consults before routing. The threat it records is
// "blocked", so the dashboard offers "Remove Mitigation / Allow IP" on it and
// promises the address can reach the services again. The release cleared the
// IP mitigation table, the eBPF shun and the reputation scores -- and never the
// honeypot's list, which nothing outside the honeypot could reach. The operator
// was told it had worked; the address stayed refused on every request until the
// ban ran out, up to a day, or the gateway restarted.
func TestReleasingAnAddressLiftsItsHoneypotBan(t *testing.T) {
	svc := newMitigationTestService(t)
	gate := honeypotGate(t)
	const ip = "203.0.113.177"

	if got := serveFrom(gate, ip, "/.env"); got != http.StatusForbidden {
		t.Fatalf("setup: a request for a trap path got %d, want 403", got)
	}
	if got := serveFrom(gate, ip, "/"); got != http.StatusForbidden {
		t.Fatalf("setup: the trap hit did not ban the address (an ordinary request got %d)", got)
	}

	res, err := svc.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{Source: ip})
	if err != nil || !res.GetSuccess() {
		t.Fatalf("release failed: err=%v msg=%q", err, res.GetMessage())
	}
	if got := serveFrom(gate, ip, "/"); got != http.StatusOK {
		t.Fatalf("after %q the released address still gets %d on every request: "+
			"the honeypot's ban survived a release the operator was told had worked",
			res.GetMessage(), got)
	}
}

// TestReleasingAnIPv6AddressLiftsItsNetworksHoneypotBan pins the release to
// the key the ban is filed under. An IPv6 ban covers the offender's /64, and
// the operator releases the one address the threat recorded; releasing that
// address rather than its /64 would find no ban, leave the whole /64 refused,
// and still report success.
func TestReleasingAnIPv6AddressLiftsItsNetworksHoneypotBan(t *testing.T) {
	svc := newMitigationTestService(t)
	gate := honeypotGate(t)
	const offender, neighbour = "2001:db8:177:1::10", "2001:db8:177:1::20"

	if got := serveFrom(gate, "["+offender+"]", "/.env"); got != http.StatusForbidden {
		t.Fatalf("setup: a request for a trap path got %d, want 403", got)
	}
	if got := serveFrom(gate, "["+neighbour+"]", "/"); got != http.StatusForbidden {
		t.Fatalf("setup: the trap hit did not ban the offender's /64 (a neighbour got %d)", got)
	}

	res, err := svc.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{Source: offender})
	if err != nil || !res.GetSuccess() {
		t.Fatalf("release failed: err=%v msg=%q", err, res.GetMessage())
	}
	for _, ip := range []string{offender, neighbour} {
		if got := serveFrom(gate, "["+ip+"]", "/"); got != http.StatusOK {
			t.Errorf("after %q, %s still gets %d: the release did not reach the /64 the "+
				"ban is filed under", res.GetMessage(), ip, got)
		}
	}
}
