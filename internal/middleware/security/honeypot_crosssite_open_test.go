// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding

package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// OPEN FINDING -- needs a design decision, see the reviewer report.
//
// TestAThirdPartyPageCannotBanItsVisitors: any web page can make its visitors'
// browsers request the gateway's trap paths -- an <img> pointing at /.env -- and
// the honeypot treats that request exactly as a scanner's. One page view bans
// the visitor's address for fifteen minutes; a page left open that loads the
// next image after each ban lapses (or a page the visitor keeps returning to)
// walks it up the whole ladder, 15m -> 1h -> 6h -> 24h, and behind CGNAT or an
// office egress it takes everyone sharing that address. Nothing about the
// requests is unusual except what the browser itself says: Sec-Fetch-Site
// cross-site, Sec-Fetch-Mode no-cors, Sec-Fetch-Dest image.
//
// The fix is not obvious, which is why this is open: those headers are written
// by the client, so honouring them is an opt-out a scanner can take by sending
// them (the shape invariant 7 forbids for deny decisions). Options include not
// escalating past the first rung on a browser-marked cross-site request,
// refusing but not banning, or accepting the risk and documenting it.
func TestAThirdPartyPageCannotBanItsVisitors(t *testing.T) {
	resetHoneypotState(t)
	const visitor = "198.51.100.199"
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := Honeypot(HoneypotConfig{Paths: defaultHoneypotPaths()})(ok)

	// What a browser sends for <img src="https://gateway/.env"> on another site.
	subresource := func(path string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = visitor + ":51000"
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Sec-Fetch-Mode", "no-cors")
		req.Header.Set("Sec-Fetch-Dest", "image")
		req.Header.Set("Referer", "https://unrelated-forum.example/thread/42")
		return req
	}
	paths := []string{"/.env", "/.git/x", "/.aws/x", "/.ssh/x"}
	for i, path := range paths {
		h.ServeHTTP(httptest.NewRecorder(), subresource(path))
		if i < len(paths)-1 {
			lapseBan(visitor) // the page's next image loads after this ban has run out
		}
	}

	blocklistMu.RLock()
	until, banned := honeypotBlocklist[visitor]
	blocklistMu.RUnlock()
	if banned {
		t.Fatalf("image loads a third-party page made from the visitor's browser banned "+
			"the visitor's address for %s", time.Until(until).Round(time.Minute))
	}
}

// lapseBan moves ip's ban into the past, as waiting it out would; its strikes
// stay, as they would inside the strike window.
func lapseBan(ip string) {
	blocklistMu.Lock()
	honeypotBlocklist[ip] = time.Now().Add(-time.Second)
	blocklistMu.Unlock()
}
