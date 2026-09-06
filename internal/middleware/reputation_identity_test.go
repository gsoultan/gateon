// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// These tests pin what a reputation-based refusal is allowed to affect.
//
// The reputation blocker used to key on the JA4+ fingerprint alone. JA4+ is
// derived entirely from the TLS stack and the shape of the HTTP headers — method,
// version, cookie-present, referer-present, header count and mask,
// Accept-Language — and reads no address, connection or credential. It therefore
// identifies a *browser configuration*, not a client, and every stock-Chrome user
// of one version and language shared a single score.
//
// The blocker is attached to every route unconditionally (router.go) and refuses
// with 403 below 2.0, so one patient attacker on an unmodified browser could
// drive that shared score to zero and lock out every other user of that browser,
// on every route. No volume was required and nothing about the traffic had to
// look unusual — looking ordinary was the attack.
//
// Root cause in one sentence: the identity enforcement hung on described the
// software making the request rather than the party making it.

// repTestClient is one simulated client: a browser class and an address.
type repTestClient struct {
	ja4Plus  string
	remoteIP string
}

// serveWithIdentity drives a request carrying an explicit fingerprint and
// address through a handler, the way the entrypoint would have populated them.
func serveWithIdentity(h http.Handler, c repTestClient) int {
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.RemoteAddr = c.remoteIP + ":51234"

	rs := &request.RequestState{JA4Plus: c.ja4Plus}
	req = req.WithContext(context.WithValue(req.Context(),
		request.RequestStateContextKey{}, rs))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// blockerHandler builds the reputation blocker over a backend that answers 200.
func blockerHandler(t *testing.T) http.Handler {
	t.Helper()
	// The blocker declines to act under GATEON_TEST unless this is set, so that
	// unrelated suites are not refused by scores they never established.
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")

	return ReputationBlocker("reputation-identity-test")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
}

// TestReputationBlockIsScopedToTheOffendersNetwork is the regression test for
// the shared-identity defect.
//
// Two clients, byte-identical browsers, different networks. One earns a score of
// zero. The other must be untouched — it is a different person who happens to
// have chosen the same browser, and there is no version of "precise blocking"
// that includes refusing them.
func TestReputationBlockIsScopedToTheOffendersNetwork(t *testing.T) {
	const sharedBrowser = "t13d1516h2_8daaf6152771_b0da82dd1658_scoped"

	offender := repTestClient{ja4Plus: sharedBrowser, remoteIP: "203.0.113.10"}
	bystander := repTestClient{ja4Plus: sharedBrowser, remoteIP: "198.51.100.20"}

	// Record the violation exactly as the threat pipeline does, through the one
	// function that decides what a score is about. A test that invented its own
	// key would prove only that the test and itself agree.
	offenderID := repid.For(offender.ja4Plus, offender.remoteIP)
	telemetry.DecreaseReputation(offenderID, 99, "test: repeated waf violations")

	h := blockerHandler(t)

	if got := serveWithIdentity(h, offender); got != http.StatusForbidden {
		t.Errorf("the offender got %d, want 403 — the client that earned the score "+
			"must still be refused, or the fix has simply disabled the control", got)
	}

	if got := serveWithIdentity(h, bystander); got != http.StatusOK {
		t.Errorf("a bystander on a different network got %d, want 200.\n"+
			"Both clients run the same browser, so they share a JA4+ — and if that "+
			"is what the 403 hangs on, one attacker locks out every user of that "+
			"browser everywhere. This is the defect the composite identity exists "+
			"to close.", got)
	}
}

// TestReputationClassScoreAloneDoesNotRefuse states the same property from the
// other side, and is the one that fails loudest against the old code.
//
// It writes a score under the bare fingerprint — precisely the key the blocker
// used to read — and requires that no client is refused because of it. A class
// with a bad score is a reason to look, never a reason to refuse.
func TestReputationClassScoreAloneDoesNotRefuse(t *testing.T) {
	const sharedBrowser = "t13d1516h2_8daaf6152771_b0da82dd1658_classonly"

	telemetry.DecreaseReputation(sharedBrowser, 99, "test: class-wide score")

	h := blockerHandler(t)

	for _, c := range []repTestClient{
		{ja4Plus: sharedBrowser, remoteIP: "203.0.113.10"},
		{ja4Plus: sharedBrowser, remoteIP: "198.51.100.20"},
		{ja4Plus: sharedBrowser, remoteIP: "2001:db8:1::5"},
	} {
		if got := serveWithIdentity(h, c); got != http.StatusOK {
			t.Errorf("client at %s got %d, want 200 — a score attached to the browser "+
				"class refused a client that never contributed to it", c.remoteIP, got)
		}
	}
}

// TestReputationScopeSeparatesNetworksNotUsers records the limit of the fix, so
// nobody reads it as more than it is.
//
// Scoping is per network, not per person. Two clients behind one NAT still share
// an identity, because from outside the gateway there is nothing to tell them
// apart — the request carries no evidence of which of them sent it. The fix
// bounds the blast radius to one network; it does not eliminate it, and claiming
// otherwise would be the same overstatement that made the original design look
// safe.
func TestReputationScopeSeparatesNetworksNotUsers(t *testing.T) {
	const sharedBrowser = "t13d1516h2_8daaf6152771_b0da82dd1658_natshared"

	neighbour := repTestClient{ja4Plus: sharedBrowser, remoteIP: "203.0.113.77"}
	offender := repTestClient{ja4Plus: sharedBrowser, remoteIP: "203.0.113.10"}

	telemetry.DecreaseReputation(
		repid.For(offender.ja4Plus, offender.remoteIP),
		99, "test: same-network offender")

	h := blockerHandler(t)

	if got := serveWithIdentity(h, neighbour); got != http.StatusForbidden {
		t.Errorf("a client sharing the offender's /24 got %d, want 403 — this test "+
			"documents that scoping is per network. If it now passes, the scope was "+
			"narrowed and this expectation should be updated deliberately rather "+
			"than discovered later.", got)
	}
}
