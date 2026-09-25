// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func limitedRoute(t *testing.T, cfg map[string]string) http.Handler {
	t.Helper()
	mw, err := NewRateLimit(cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewRateLimit: %v", err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
}

// browserRequest is a request whose headers -- and so JA4H -- are identical
// whatever address it comes from.
func browserRequest(remote string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "en-US")
	r.RemoteAddr = remote
	return r
}

func statusOf(h http.Handler, r *http.Request) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

// TestTenantStrategyLimitsRequestsWithoutATenant sends unauthenticated requests
// through a limit keyed per tenant. The key came back empty for them, and an
// empty key skipped limiting, so they were never limited at all.
func TestTenantStrategyLimitsRequestsWithoutATenant(t *testing.T) {
	h := limitedRoute(t, map[string]string{"strategy": "tenant", "requests_per_minute": "1", "burst": "1"})
	limited := 0
	for range 5 {
		if statusOf(h, browserRequest("198.51.100.31:4000")) == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("5 requests with no tenant at 1/min, burst 1: none was limited")
	}
}

// TestFingerprintStrategyDoesNotShareABucketAcrossNetworks: one client uses up
// a JA4H-keyed limit; a client on another network with the same browser must
// still get through. Keyed on the browser class alone, it got 429 on its first
// request.
func TestFingerprintStrategyDoesNotShareABucketAcrossNetworks(t *testing.T) {
	for _, strategy := range []string{"ja4h", "fingerprint"} {
		t.Run(strategy, func(t *testing.T) {
			h := limitedRoute(t, map[string]string{"strategy": strategy, "requests_per_minute": "1", "burst": "1"})
			limited := false
			for range 5 {
				limited = statusOf(h, browserRequest("198.51.100.32:4000")) == http.StatusTooManyRequests || limited
			}
			if !limited {
				t.Fatal("5 requests from one client at 1/min, burst 1: none was limited")
			}
			if got := statusOf(h, browserRequest("203.0.113.32:4000")); got != http.StatusOK {
				t.Fatalf("a client on another network with the same browser got %d on its first request", got)
			}
		})
	}
}

// TestNewClientGetsTheConfiguredBurst: a client with no reputation history
// scores 100, and the limit divided by 50, so it got twice the burst the
// operator set.
func TestNewClientGetsTheConfiguredBurst(t *testing.T) {
	h := limitedRoute(t, map[string]string{"requests_per_minute": "60", "burst": "5"})
	passed := 0
	for range 10 {
		if statusOf(h, browserRequest("198.51.100.33:4000")) == http.StatusOK {
			passed++
		}
	}
	if passed != 5 {
		t.Fatalf("burst 5: %d back-to-back requests passed, want 5", passed)
	}
}
