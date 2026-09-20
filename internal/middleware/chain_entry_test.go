// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
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

// TestRealIPGlobalResolvesWithoutTrustingTheClient covers the default posture.
// With no global config loaded, EffectiveTrustCloudflare falls back to the
// environment, which is unset here -- so a client-written X-Forwarded-For must
// not become the resolved address.
func TestRealIPGlobalResolvesWithoutTrustingTheClient(t *testing.T) {
	var resolved string
	h := RealIPGlobal()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resolved = r.RemoteAddr
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.9:1234"
	req.Header.Set("CF-Connecting-IP", "203.0.113.200")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if resolved == "" {
		t.Fatal("RealIPGlobal left RemoteAddr empty")
	}
	if resolved == "203.0.113.200" || resolved == "203.0.113.200:1234" {
		t.Errorf("RemoteAddr = %q: an untrusted CF-Connecting-IP became the "+
			"resolved client address, so any client could pick its own", resolved)
	}
}

// TestCheckBreakerOpensOnlyAfterEnoughRequests pins the guard that keeps a
// breaker from tripping on a tiny sample. Two failures out of two is a 100%
// error rate and would open a breaker judged on rate alone -- which is how a
// route gets cut off by the first two requests after a deploy.
func TestCheckBreakerOpensOnlyAfterEnoughRequests(t *testing.T) {
	cfg := CircuitBreakerConfig{
		RouteID:        "cb-test",
		WindowSize:     time.Millisecond,
		MinRequests:    10,
		ErrorThreshold: 0.5,
	}

	s := &circuitBreakerState{state: telemetry.CircuitClosed, lastReset: time.Now().Add(-time.Hour)}
	s.requests.Store(2)
	s.errors.Store(2)
	s.checkBreaker(cfg)

	if s.state != telemetry.CircuitClosed {
		t.Errorf("state = %v after 2 failures of 2, want closed: MinRequests is "+
			"%d, and a breaker that trips on a two-request sample cuts a route "+
			"off on the first traffic after a deploy", s.state, cfg.MinRequests)
	}

	// Same rate, enough requests: now it must open.
	s.lastReset = time.Now().Add(-time.Hour)
	s.requests.Store(20)
	s.errors.Store(15)
	s.checkBreaker(cfg)

	if s.state != telemetry.CircuitOpen {
		t.Errorf("state = %v after 15 failures of 20 against a %.0f%% threshold, "+
			"want open", s.state, cfg.ErrorThreshold*100)
	}
}

// TestCheckBreakerHalfOpenNeedsACleanWindow covers recovery. A half-open
// breaker that sees any error goes straight back to open; one that sees none
// closes. Getting this backwards either pins a broken route open forever or
// re-admits traffic to one that is still failing.
func TestCheckBreakerHalfOpenNeedsACleanWindow(t *testing.T) {
	cfg := CircuitBreakerConfig{RouteID: "cb-half", WindowSize: time.Millisecond, MinRequests: 1}

	dirty := &circuitBreakerState{state: telemetry.CircuitHalfOpen, lastReset: time.Now().Add(-time.Hour)}
	dirty.requests.Store(5)
	dirty.errors.Store(1)
	dirty.checkBreaker(cfg)
	if dirty.state != telemetry.CircuitOpen {
		t.Errorf("half-open with 1 error = %v, want open", dirty.state)
	}

	clean := &circuitBreakerState{state: telemetry.CircuitHalfOpen, lastReset: time.Now().Add(-time.Hour)}
	clean.requests.Store(5)
	clean.errors.Store(0)
	clean.checkBreaker(cfg)
	if clean.state != telemetry.CircuitClosed {
		t.Errorf("half-open with no errors = %v, want closed; the route would "+
			"never recover", clean.state)
	}
}
