// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// A reputation score was kept for the whole JA4+ fingerprint scoped to the
// client's network, and half of JA4+ is chosen by the client per request: JA4H
// is the method, the HTTP version, whether a Cookie and a Referer were sent, and
// which of Accept-Language and User-Agent were. So a client the reputation
// blocker refused was a new, neutral-scored client again the moment it dropped
// its Referer -- or sent a cookie, or switched from GET to POST. The blocker was
// weakest against exactly the client it exists for.
//
// Root cause in one sentence: the identity a refusal hung on included bits the
// refused client chooses afresh on every request.

// toggledClient builds one client's requests as the entrypoint hands them to
// the middlewares: the request state carries the TLS fingerprint (empty for a
// plaintext client) and the JA4H and JA4+ derived from each request's headers.
type toggledClient struct {
	ip, ja4 string
}

// request is the client's GET for /account as a stock browser sends it, with
// edit applied first -- the toggle under test.
func (c toggledClient) request(edit func(*http.Request)) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.RemoteAddr = c.ip + ":40000"
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Referer", "https://shop.example/cart")
	if edit != nil {
		edit(req)
	}
	ja4h := telemetry.GenerateJA4H(req)
	rs := &request.RequestState{JA4: c.ja4, JA4H: ja4h, JA4Plus: c.ja4 + "_" + ja4h}
	return req.WithContext(request.WithState(req.Context(), rs))
}

// perRequestToggles are the things a browser changes from one request to the
// next, and so the things a refused client could change to be someone new.
var perRequestToggles = map[string]func(*http.Request){
	"drops its Referer": func(r *http.Request) { r.Header.Del("Referer") },
	"sends a cookie":    func(r *http.Request) { r.Header.Set("Cookie", "sid=1") },
	"switches to POST":  func(r *http.Request) { r.Method = http.MethodPost },
	"sends a HEAD":      func(r *http.Request) { r.Method = http.MethodHead },
	"does all of them at once": func(r *http.Request) {
		r.Header.Del("Referer")
		r.Header.Set("Cookie", "sid=1")
		r.Method = http.MethodPut
	},
}

// refuseClient gives c the score two WAF blocks earn, under the identity its
// request resolves to, and checks the blocker refuses it.
func refuseClient(t *testing.T, h http.Handler, c toggledClient) {
	t.Helper()
	first := c.request(nil)
	id := telemetry.GetReputationID(first)
	t.Cleanup(func() { telemetry.ResetReputation(id) })
	telemetry.DecreaseReputation(id, 50, "waf_blocked")
	telemetry.DecreaseReputation(id, 50, "waf_blocked")
	if got := serveCode(h, c.request(nil)); got != http.StatusForbidden {
		t.Fatalf("setup: the client was not refused after earning a score of zero (got %d)", got)
	}
}

func serveCode(h http.Handler, req *http.Request) int {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// TestTogglingAHeaderDoesNotShedAReputationBlock is the regression test, for a
// plaintext client -- whose identity comes from JA4H alone -- and a TLS one.
func TestTogglingAHeaderDoesNotShedAReputationBlock(t *testing.T) {
	h := blockerHandler(t)
	for name, c := range map[string]toggledClient{
		"plaintext": {ip: "192.0.2.230"},
		"tls":       {ip: "192.0.2.231", ja4: "t13d1516h2_8daaf6152771_b0da82dd1658"},
	} {
		t.Run(name, func(t *testing.T) {
			refuseClient(t, h, c)
			for toggle, edit := range perRequestToggles {
				next := c.request(edit)
				if got := serveCode(h, next); got != http.StatusForbidden {
					t.Errorf("the refused client %s and got %d: its identity became %q, a fresh "+
						"neutral score", toggle, got, telemetry.GetReputationID(next))
				}
			}
		})
	}
}

// TestATLSClientCannotShedABlockThroughItsHTTPHeaders: with a TLS fingerprint
// the class is the TLS fingerprint alone, so no header -- not even which of
// User-Agent and Accept-Language it sends, which a plaintext client's class
// still reads -- moves a TLS client to a new score.
func TestATLSClientCannotShedABlockThroughItsHTTPHeaders(t *testing.T) {
	h := blockerHandler(t)
	c := toggledClient{ip: "192.0.2.232", ja4: "t13d1516h2_8daaf6152771_b0da82dd1658"}
	refuseClient(t, h, c)

	for toggle, edit := range map[string]func(*http.Request){
		"drops its User-Agent":      func(r *http.Request) { r.Header.Del("User-Agent") },
		"drops its Accept-Language": func(r *http.Request) { r.Header.Del("Accept-Language") },
		"speaks HTTP/1.0":           func(r *http.Request) { r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/1.0", 1, 0 },
	} {
		if got := serveCode(h, c.request(edit)); got != http.StatusForbidden {
			t.Errorf("the refused TLS client %s and got %d", toggle, got)
		}
	}
}

// TestTheClassStillSeparatesClientSoftware is the collateral bound. A score
// still belongs to one kind of client on one network, not to the network: a
// different TLS stack on the refused client's /24, or a plaintext client that is
// not a browser, is not refused for what the browser did.
func TestTheClassStillSeparatesClientSoftware(t *testing.T) {
	h := blockerHandler(t)

	refuseClient(t, h, toggledClient{ip: "192.0.2.233", ja4: "t13d1516h2_8daaf6152771_b0da82dd1658"})
	otherStack := toggledClient{ip: "192.0.2.234", ja4: "t13d1715h2_5b57614c22b0_3d5424432f57"}
	if got := serveCode(h, otherStack.request(nil)); got != http.StatusOK {
		t.Errorf("a client with a different TLS stack on the refused client's network got %d, want 200", got)
	}

	refuseClient(t, h, toggledClient{ip: "198.51.100.233"})
	curl := toggledClient{ip: "198.51.100.234"}.request(func(r *http.Request) {
		r.Header.Del("Accept-Language")
		r.Header.Set("User-Agent", "curl/8.9.1")
	})
	if got := serveCode(h, curl); got != http.StatusOK {
		t.Errorf("a plaintext client that is not a browser, on a refused browser's network, got %d, want 200", got)
	}
}
