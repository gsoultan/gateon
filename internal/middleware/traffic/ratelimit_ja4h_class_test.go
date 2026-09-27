// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// TestTheJA4HStrategyIsNotShedByAPerRequestToggle: the "ja4h" rate-limit
// strategy keys a client's bucket on its JA4H within its network, and JA4H
// carries the method and whether a Cookie and a Referer were sent. Keyed on
// those, a client at its limit got a fresh bucket by dropping its Referer --
// the evasion ADR 0024 closes for reputation, through the same repid.For. The
// bucket still separates what a client does not vary: a client that is not a
// browser has its own.
func TestTheJA4HStrategyIsNotShedByAPerRequestToggle(t *testing.T) {
	build := func(method string, headers map[string]string) *http.Request {
		req := httptest.NewRequest(method, "/api/orders", nil)
		req.RemoteAddr = "192.0.2.61:40000"
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return req.WithContext(request.WithState(req.Context(), &request.RequestState{}))
	}
	browser := map[string]string{"User-Agent": "Mozilla/5.0 Chrome/140.0", "Accept-Language": "en-US"}
	withReferer := map[string]string{
		"User-Agent": "Mozilla/5.0 Chrome/140.0", "Accept-Language": "en-US", "Referer": "https://shop.example/",
	}
	withCookie := map[string]string{
		"User-Agent": "Mozilla/5.0 Chrome/140.0", "Accept-Language": "en-US", "Cookie": "sid=1",
	}

	base := PerJA4H(build(http.MethodGet, withReferer))
	for what, req := range map[string]*http.Request{
		"dropping its Referer": build(http.MethodGet, browser),
		"sending a cookie":     build(http.MethodGet, withCookie),
		"switching to POST":    build(http.MethodPost, withReferer),
	} {
		if got := PerJA4H(req); got != base {
			t.Errorf("the ja4h bucket changed from %q to %q by %s: a client at its limit gets a fresh one", base, got, what)
		}
	}
	if curl := PerJA4H(build(http.MethodGet, map[string]string{"User-Agent": "curl/8.9.1"})); curl == base {
		t.Errorf("a client that is not a browser shares the browser's bucket %q", base)
	}
}
