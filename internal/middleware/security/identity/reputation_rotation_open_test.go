// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding

package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// OPEN FINDING -- needs a design decision, see the reviewer report.
//
// TestTogglingAHeaderDoesNotShedAReputationBlock: the identity a score hangs on
// is JA4+ scoped to a network, and both halves of JA4+ are chosen by the
// client. JA4H is the method, the HTTP version, whether a Cookie and a Referer
// are present, and which of Accept-Language and User-Agent are present; JA4 is
// the TLS offer, including hashes of the cipher and extension lists. So a
// client the reputation blocker refuses is a new, neutral-scored client again
// the moment it drops its Referer -- a handful of such toggles per method from
// headers alone, and an unbounded number from a TLS stack that varies its
// cipher offer per connection. ADR 0011 names this "inverse failure" in its
// context; its decision does not address it, and the blocker stays weakest
// against the client it exists for. Fixing it means deciding what, besides
// the network, a score may hang on (for instance a network-level score
// consulted alongside the fingerprinted one).
func TestTogglingAHeaderDoesNotShedAReputationBlock(t *testing.T) {
	h := blockerHandler(t)
	const ip = "203.0.113.230"

	// Requests as the entrypoint leaves them: a fresh request state, the
	// fingerprint derived from the headers on first use.
	browser := func(referer string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/account", nil)
		req.RemoteAddr = ip + ":40000"
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0")
		req.Header.Set("Accept-Language", "en-US")
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		return req.WithContext(request.WithState(req.Context(), &request.RequestState{}))
	}
	serve := func(req *http.Request) int {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	// The client earns a refusal the way the store records one: two WAF blocks
	// under the identity its request resolves to.
	first := browser("https://shop.example/cart")
	id := telemetry.GetReputationID(first)
	t.Cleanup(func() { telemetry.ResetReputation(id) })
	telemetry.DecreaseReputation(id, 50, "waf_blocked")
	telemetry.DecreaseReputation(id, 50, "waf_blocked")
	if got := serve(browser("https://shop.example/cart")); got != http.StatusForbidden {
		t.Fatalf("setup: the client was not refused after earning a score of zero (got %d)", got)
	}

	next := browser("")
	if got := serve(next); got != http.StatusForbidden {
		t.Fatalf("the same client on the same address dropped its Referer and got %d: "+
			"its identity went from %q to %q, a fresh neutral score",
			got, id, telemetry.GetReputationID(next))
	}
}
