// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// EntryPoint is the first middleware on every chain and the only place that
// resolves the client IP, the country, the request ID and the fingerprints.
// Everything downstream reads its RequestState instead of recomputing, so a
// field it fails to populate is a field the whole chain sees as empty -- and
// several of those fields are what security decisions are keyed on.

func TestEntryPointPopulatesTheStateTheChainReads(t *testing.T) {
	var got *request.RequestState
	h := EntryPoint("ep-1", "public", false)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Copied, not retained: the state goes back to a pool when EntryPoint
		// returns, so holding the pointer would read whatever the next request
		// puts in it.
		if rs := request.GetRequestState(r); rs != nil {
			c := *rs
			got = &c
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com:8443/api", nil)
	req.RemoteAddr = "203.0.113.5:44321"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got == nil {
		t.Fatal("no RequestState reached the handler; every middleware " +
			"downstream would fall back to recomputing or to a zero value")
	}
	if got.EntryPointID != "ep-1" {
		t.Errorf("EntryPointID = %q, want %q", got.EntryPointID, "ep-1")
	}
	if got.RouteName != "gateon-public" {
		t.Errorf("RouteName = %q, want %q", got.RouteName, "gateon-public")
	}
	if got.IsManagement {
		t.Error("IsManagement = true for a non-management entrypoint; the WAF " +
			"skips management traffic, so this flag set wrongly disables it")
	}
	if got.ClientRemoteAddr == "" {
		t.Error("ClientRemoteAddr is empty; every IP-keyed decision downstream " +
			"would see no client")
	}
	// StripPort, not the raw Host: a vhost match against "example.com:8443"
	// fails against a route configured for "example.com".
	if got.StrippedHost != "example.com" {
		t.Errorf("StrippedHost = %q, want %q", got.StrippedHost, "example.com")
	}
	if got.RequestID == "" {
		t.Error("RequestID is empty; nothing in the logs would correlate")
	}
	if got.TEntrypoint == 0 {
		t.Error("TEntrypoint is zero; request timing would measure from the epoch")
	}
}

// TestEntryPointHonoursAnInboundRequestID keeps a caller's correlation id
// rather than minting a new one, and echoes it back either way, so a client or
// an upstream proxy can follow a request through.
func TestEntryPointHonoursAnInboundRequestID(t *testing.T) {
	var seen string
	h := EntryPoint("ep", "label", true)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = request.GetRequestState(r).RequestID
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "caller-supplied-id")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if seen != "caller-supplied-id" {
		t.Errorf("RequestID = %q, want the inbound header value", seen)
	}
	if echoed := rr.Header().Get("X-Request-ID"); echoed != "caller-supplied-id" {
		t.Errorf("response X-Request-ID = %q, want it echoed back", echoed)
	}
}

// TestEntryPointMarksManagementTraffic guards the flag the WAF's deduplication
// reads to skip inspection entirely. Set wrongly on a public entrypoint it
// would disable the WAF for that entrypoint.
func TestEntryPointMarksManagementTraffic(t *testing.T) {
	var isMgmt bool
	h := EntryPoint("mgmt", "mgmt", true)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		isMgmt = request.GetRequestState(r).IsManagement
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if !isMgmt {
		t.Error("IsManagement = false for a management entrypoint")
	}
}

func TestFingerprintingPassesTheRequestThrough(t *testing.T) {
	called := false
	h := Fingerprinting()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if !called {
		t.Fatal("Fingerprinting did not call the next handler")
	}
	if rr.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusTeapot)
	}
}

// RealIPGlobal picks between RealIP(true) and RealIP(false) on
// config.EffectiveTrustCloudflare(), which is a sync.OnceValue over an
// environment variable -- resolved once per process, so t.Setenv cannot flip it
// from inside a test that runs after anything else has read it. The selection
// is therefore untested here, deliberately and visibly; what is tested is the
// resolution it selects between, which is where a mistake would actually live.
//
// Both directions matter. Asserting only the untrusted case is worthless: with
// trust off, "resolve correctly" and "do nothing at all" produce the same
// RemoteAddr, so a middleware stubbed to a bare pass-through passes. Only the
// trusted case, where the header *must* be honoured, tells them apart.

func TestRealIPDoesNotTrustAnUnverifiedHeader(t *testing.T) {
	const peer = "198.51.100.9"

	var resolved string
	h := RealIP(false)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resolved = r.RemoteAddr
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = peer + ":1234"
	req.Header.Set("CF-Connecting-IP", "203.0.113.200")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if host := hostOf(resolved); host != peer {
		t.Errorf("RemoteAddr = %q, want the socket peer %q: an untrusted "+
			"CF-Connecting-IP became the client address, so any client could "+
			"pick its own", host, peer)
	}
}

// TestRealIPHonoursTheHeaderWhenTrusted pins a second condition the flag name
// hides: trustCloudflare alone is not enough. GetClientIP requires the *peer*
// to qualify too -- either a configured trusted proxy, or an address inside
// Cloudflare's own ranges -- so a request arriving straight from the internet
// with a CF-Connecting-IP is ignored even with the flag on. Loopback does not
// qualify either unless GATEON_TRUSTED_PROXIES names it.
//
// I wrote this test twice expecting the flag to be sufficient, and it failed
// both times. That is the property worth pinning: a header that names the
// client is honoured only when the hop that added it is one we trust.
//
// The peer below is inside 104.16.0.0/13, one of the Cloudflare ranges
// internal/request registers at init. That avoids GATEON_TRUSTED_PROXIES,
// which is read once at package load and so cannot be set from a test.
func TestRealIPHonoursTheHeaderWhenTrusted(t *testing.T) {
	const claimed = "203.0.113.200"

	var resolved string
	h := RealIP(true)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resolved = r.RemoteAddr
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "104.16.0.1:1234"
	req.Header.Set("CF-Connecting-IP", claimed)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if host := hostOf(resolved); host != claimed {
		t.Errorf("RemoteAddr = %q, want %q from a trusted peer's "+
			"CF-Connecting-IP: behind Cloudflare every request would be "+
			"attributed to the edge rather than to the client", host, claimed)
	}
}

// TestRealIPGlobalRewritesRemoteAddrFromResolvedState covers RealIPGlobal
// itself rather than the RealIP variants it selects between.
//
// The selection is not controllable from a test, but the rewrite is, and it is
// observable regardless of which variant runs: GetClientIP returns
// RequestState.ClientRemoteAddr when the chain has already resolved one, so a
// middleware that actually calls it rewrites RemoteAddr to that address while
// preserving the port. A pass-through leaves the socket peer untouched.
//
// This exists because the test it replaces asserted only "non-empty, and not
// the header value", which a pass-through satisfies -- and deleting it in
// favour of the RealIP tests above moved the coverage into another package and
// left RealIPGlobal with none.
func TestRealIPGlobalRewritesRemoteAddrFromResolvedState(t *testing.T) {
	const resolvedByChain = "10.0.0.5"

	var seen string
	h := RealIPGlobal()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.RemoteAddr
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.9:1234"
	req = req.WithContext(request.WithState(req.Context(),
		&request.RequestState{ClientRemoteAddr: resolvedByChain}))

	h.ServeHTTP(httptest.NewRecorder(), req)

	if hostOf(seen) != resolvedByChain {
		t.Errorf("RemoteAddr = %q, want the address the chain already resolved "+
			"(%q): RealIPGlobal did not resolve at all, so every downstream "+
			"middleware reading RemoteAddr sees the immediate peer instead of "+
			"the client", seen, resolvedByChain)
	}
	if _, port, err := net.SplitHostPort(seen); err != nil || port != "1234" {
		t.Errorf("RemoteAddr = %q, want the original port preserved; PROXY "+
			"protocol generation expects host:port", seen)
	}
}

func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
