// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/testutil"
)

func newTestOIDC(t *testing.T, issuer string, timeout, retry time.Duration) http.Handler {
	t.Helper()
	mw, err := OIDCProxy(OIDCProxyConfig{
		Issuer:                 issuer,
		ClientID:               "gateon-client",
		ClientSecret:           "secret",
		RedirectURL:            "https://app.example.com/auth/callback",
		RouteID:                "r1",
		DiscoveryTimeout:       timeout,
		DiscoveryRetryInterval: retry,
	})
	if err != nil {
		t.Fatalf("OIDCProxy: %v", err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("backend"))
	}))
}

func serveOIDC(h http.Handler, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

// TestOIDCFailsClosedUntilTheProviderRecovers covers what discovery at first
// use has to get right: while the provider cannot be reached the route refuses
// rather than serving unauthenticated, and once it can, login works again
// without a restart or a config edit.
func TestOIDCFailsClosedUntilTheProviderRecovers(t *testing.T) {
	idp := testutil.NewFakeOIDCProvider(t, "gateon-client")
	idp.DiscoveryDown.Store(true)
	// A nanosecond, not zero: zero selects the default interval.
	h := newTestOIDC(t, idp.Issuer(), 5*time.Second, time.Nanosecond)

	rec := serveOIDC(h, "https://app.example.com/dashboard")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("provider down: status %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "backend") {
		t.Fatal("provider down: the request reached the backend unauthenticated")
	}

	idp.DiscoveryDown.Store(false)
	rec = serveOIDC(h, "https://app.example.com/dashboard")
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), idp.Issuer()+"/authorize") {
		t.Fatalf("provider back: status %d Location %q, want 302 to the provider",
			rec.Code, rec.Header().Get("Location"))
	}
}

// TestOIDCBacksOffDiscoveryWhileTheProviderIsDown keeps a burst of traffic to
// a route whose provider is down from turning into a burst of discovery
// requests against that provider.
func TestOIDCBacksOffDiscoveryWhileTheProviderIsDown(t *testing.T) {
	idp := testutil.NewFakeOIDCProvider(t, "gateon-client")
	idp.DiscoveryDown.Store(true)
	h := newTestOIDC(t, idp.Issuer(), 5*time.Second, time.Hour)

	for i := range 20 {
		if rec := serveOIDC(h, "https://app.example.com/"); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("request %d: status %d, want 503", i, rec.Code)
		}
	}
	if n := idp.DiscoveryCalls.Load(); n != 1 {
		t.Fatalf("20 requests inside one retry interval made %d discovery calls, want 1", n)
	}
}

// TestOIDCDiscoveryIsBoundedByItsTimeout sends a request to a route whose
// provider accepts the connection and never answers. The request has to be
// refused once the discovery timeout passes, not held for as long as the
// provider hangs.
func TestOIDCDiscoveryIsBoundedByItsTimeout(t *testing.T) {
	hung := testutil.HungServer(t)
	h := newTestOIDC(t, hung.URL, 200*time.Millisecond, time.Hour)

	done := make(chan int, 1)
	go func() { done <- serveOIDC(h, "https://app.example.com/").Code }()
	select {
	case code := <-done:
		if code != http.StatusServiceUnavailable {
			t.Fatalf("hung provider: status %d, want 503", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request waited on a hung provider past the discovery timeout")
	}
}
