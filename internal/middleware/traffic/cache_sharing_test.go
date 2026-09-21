// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The response cache is the one piece of this package where a bug is a data
// leak rather than a slowdown. Three functions decide who sees whose response:
// cacheBypass decides whether a reply is too caller-specific to store at all,
// cacheKey decides what a stored reply is filed under, and
// responseAllowsCaching decides whether the origin permitted storage. Each is
// a pure function, and none of them had a test.

// TestCacheBypassRefusesCallerSpecificRequests covers the leak directly. A
// request carrying credentials gets a response computed for that identity, and
// the cache key does not mention the identity -- so storing one hands the next
// caller someone else's data.
func TestCacheBypassRefusesCallerSpecificRequests(t *testing.T) {
	cases := []struct {
		name   string
		header string
		value  string
		want   bool
	}{
		{"authorization", "Authorization", "Bearer abc", true},
		{"proxy authorization", "Proxy-Authorization", "Basic abc", true},
		{"cookie", "Cookie", "session=abc", true},
		// Not identity, but a fragment: caching a 206 would serve five bytes to
		// a client that asked for the whole resource.
		{"range", "Range", "bytes=0-4", true},
		{"ordinary request", "Accept", "text/html", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			r.Header.Set(tc.header, tc.value)
			if got := cacheBypass(r); got != tc.want {
				t.Errorf("cacheBypass with %s = %v, want %v; a stored response "+
					"is served to every later caller with the same key",
					tc.header, got, tc.want)
			}
		})
	}
}

// TestCacheKeySeparatesEverythingThatSelectsAResponse is the other half of the
// same property. Anything that changes which response the origin returns has
// to change the key, or two different responses collide on one entry.
func TestCacheKeySeparatesEverythingThatSelectsAResponse(t *testing.T) {
	base := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://a.example/p?q=1", nil)
		r.Host = "a.example"
		return r
	}

	ref := cacheKey("route-a", base())

	t.Run("route", func(t *testing.T) {
		if cacheKey("route-b", base()) == ref {
			t.Error("two routes share a key; the Redis backend is shared by " +
				"every route in every instance of the cluster")
		}
	})

	t.Run("method", func(t *testing.T) {
		r := base()
		r.Method = http.MethodHead
		if cacheKey("route-a", r) == ref {
			t.Error("HEAD and GET share a key, so a HEAD could answer a GET")
		}
	})

	t.Run("host", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://b.example/p?q=1", nil)
		r.Host = "b.example"
		if cacheKey("route-a", r) == ref {
			t.Error("two virtual hosts share a key; one gateway fronts many")
		}
	})

	t.Run("query", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://a.example/p?q=2", nil)
		r.Host = "a.example"
		if cacheKey("route-a", r) == ref {
			t.Error("two query strings share a key")
		}
	})

	// The parts are length-prefixed so no content can forge a different
	// decomposition. This is the case that was actually broken: joined with a
	// bare NUL, cacheKey("x\x00GET", POST) and cacheKey("x", "GET\x00POST")
	// produced the identical string, which is one route being served another
	// route's cached responses.
	//
	// The first version of this test compared two keys that differed only in
	// length and passed with the separator removed entirely, so it asserted
	// nothing. This pair collides unless the encoding is genuinely unambiguous.
	t.Run("no content can forge a different decomposition", func(t *testing.T) {
		shifted := httptest.NewRequest(http.MethodPost, "http://a.example/p?q=1", nil)
		shifted.Host = "a.example"

		straight := httptest.NewRequest(http.MethodGet, "http://a.example/p?q=1", nil)
		straight.Host = "a.example"
		straight.Method = "GET\x00POST"

		if cacheKey("x\x00GET", shifted) == cacheKey("x", straight) {
			t.Error("two different (route, method) pairs produced one cache key; " +
				"a separator that can appear inside a part is not a separator")
		}
	})
}

// TestResponseAllowsCachingHonoursTheOrigin covers the directives that mean
// "do not store this". Getting any of them wrong stores a response the origin
// said was private, and the cache has no way to learn otherwise later.
func TestResponseAllowsCachingHonoursTheOrigin(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
		want bool
	}{
		{"plain", http.Header{}, true},
		{"set-cookie", http.Header{"Set-Cookie": {"a=b"}}, false},
		{"content-encoding", http.Header{"Content-Encoding": {"gzip"}}, false},
		{"no-store", http.Header{"Cache-Control": {"no-store"}}, false},
		{"no-cache", http.Header{"Cache-Control": {"no-cache"}}, false},
		{"private", http.Header{"Cache-Control": {"private"}}, false},
		{"mixed case directive", http.Header{"Cache-Control": {"No-Store"}}, false},
		{"public", http.Header{"Cache-Control": {"public, max-age=60"}}, true},
		// Vary on anything but Accept-Encoding means the response depends on a
		// request header the key does not include.
		{"vary accept-encoding", http.Header{"Vary": {"Accept-Encoding"}}, true},
		{"vary cookie", http.Header{"Vary": {"Cookie"}}, false},
		{"vary list with a second field", http.Header{"Vary": {"Accept-Encoding, Authorization"}}, false},
		{"vary across two headers", http.Header{"Vary": {"Accept-Encoding", "Origin"}}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := responseAllowsCaching(tc.h); got != tc.want {
				t.Errorf("responseAllowsCaching(%v) = %v, want %v", tc.h, got, tc.want)
			}
		})
	}
}
