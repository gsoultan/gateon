// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	redigo "github.com/redis/go-redis/v9"
)

// buildCacheMW builds the cache middleware the way ApplyRouteMiddlewares does:
// through the factory, from the route's config map, for a named route.
func buildCacheMW(t *testing.T, f *Factory, cfg map[string]string, route string, origin http.Handler) http.Handler {
	t.Helper()
	mw, err := f.Create(&gateonv1.Middleware{Type: "cache", Config: cfg}, route)
	if err != nil {
		t.Fatalf("create cache middleware: %v", err)
	}
	return mw(origin)
}

// hostReq builds an origin-form request (path only, Host header set), which is
// what a real client sends; an absolute-URL target would put the host into
// r.URL and mask a key that ignores r.Host.
func hostReq(host, path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	return req
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestCacheDoesNotServeOneClientsResponseToAnother(t *testing.T) {
	for _, hdr := range []string{"Authorization", "Cookie"} {
		t.Run(hdr, func(t *testing.T) {
			origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"caller":"` + r.Header.Get(hdr) + `"}`))
			})
			f := NewFactory(nil, nil, nil, nil, t.TempDir())
			h := buildCacheMW(t, f, map[string]string{"ttl_seconds": "60"}, "route-a", origin)

			reqA := hostReq("api.example", "/me")
			reqA.Header.Set(hdr, "user-a")
			serve(h, reqA)

			reqB := hostReq("api.example", "/me")
			reqB.Header.Set(hdr, "user-b")
			got := serve(h, reqB).Body.String()
			if strings.Contains(got, "user-a") {
				t.Fatalf("%s: user B was served user A's cached response: %s", hdr, got)
			}
		})
	}
}

func TestCacheDoesNotStoreUncacheableResponses(t *testing.T) {
	cases := []struct {
		name string
		set  func(h http.Header)
	}{
		{"set-cookie", func(h http.Header) { h.Set("Set-Cookie", "session=abc; HttpOnly") }},
		{"cache-control private", func(h http.Header) { h.Set("Cache-Control", "private, max-age=60") }},
		{"cache-control no-store", func(h http.Header) { h.Set("Cache-Control", "no-store") }},
		{"cache-control no-cache", func(h http.Header) { h.Set("Cache-Control", "no-cache") }},
		{"vary star", func(h http.Header) { h.Set("Vary", "*") }},
		{"vary cookie", func(h http.Header) { h.Set("Vary", "Accept-Encoding, Cookie") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				tc.set(w.Header())
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("body"))
			})
			f := NewFactory(nil, nil, nil, nil, t.TempDir())
			h := buildCacheMW(t, f, map[string]string{"ttl_seconds": "60"}, "route-a", origin)

			serve(h, hostReq("a.example", "/x"))
			rr := serve(h, hostReq("a.example", "/x"))
			if hits.Load() != 2 {
				t.Fatalf("origin hit %d times: the response was stored and replayed", hits.Load())
			}
			if rr.Header().Get("Set-Cookie") != "" && tc.name != "set-cookie" {
				t.Fatalf("unexpected Set-Cookie on replay: %q", rr.Header().Get("Set-Cookie"))
			}
		})
	}
}

func TestCacheDoesNotReplayPartialContent(t *testing.T) {
	const full = "0123456789"
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			w.Header().Set("Content-Range", "bytes 0-4/10")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte(full[:5]))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(full))
	})
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	h := buildCacheMW(t, f, map[string]string{"ttl_seconds": "60"}, "route-a", origin)

	ranged := hostReq("a.example", "/blob")
	ranged.Header.Set("Range", "bytes=0-4")
	serve(h, ranged)

	rr := serve(h, hostReq("a.example", "/blob"))
	if rr.Code != http.StatusOK || rr.Body.String() != full {
		t.Fatalf("plain GET after a Range request got %d %q; want 200 %q", rr.Code, rr.Body.String(), full)
	}
}

func TestCacheKeyIncludesHost(t *testing.T) {
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("served for " + r.Host))
	})
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	h := buildCacheMW(t, f, map[string]string{"ttl_seconds": "60"}, "catch-all", origin)

	serve(h, hostReq("tenant-a.example", "/"))
	got := serve(h, hostReq("tenant-b.example", "/")).Body.String()
	if got != "served for tenant-b.example" {
		t.Fatalf("tenant B got %q: the key ignores Host", got)
	}
}

func TestCacheDoesNotStoreTruncatedBody(t *testing.T) {
	big := strings.Repeat("x", 3*1024) // over max_body_kb=1
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(big))
	})
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	h := buildCacheMW(t, f, map[string]string{"ttl_seconds": "60", "max_body_kb": "1"}, "route-a", origin)

	serve(h, hostReq("a.example", "/big"))
	rr := serve(h, hostReq("a.example", "/big"))
	if rr.Body.Len() != len(big) {
		t.Fatalf("second response is %d bytes, want %d: a body cut at max_body_kb was cached", rr.Body.Len(), len(big))
	}
}

func TestCacheMissKeepsHeadersOfImplicitStatusResponse(t *testing.T) {
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`)) // no explicit WriteHeader: net/http sends 200 on first Write
	})
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	h := buildCacheMW(t, f, map[string]string{"ttl_seconds": "60"}, "route-a", origin)

	rr := serve(h, hostReq("a.example", "/implicit"))
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("miss response Content-Type = %q, want application/json: recorder dropped the origin's headers", got)
	}
}

func TestCacheStoreOrderIsBoundedAcrossExpiry(t *testing.T) {
	s := &cacheStore{entries: make(map[string]*cacheEntry), max: 4, maxBody: 1024}
	for i := range 10_000 {
		key := "k" + strconv.Itoa(i%3) // stays under max, so count-based eviction never runs
		s.set(key, &cacheEntry{body: []byte("v"), expireAt: time.Now().Add(-time.Second)})
		if s.get(key) != nil {
			t.Fatal("an expired entry must not be returned")
		}
	}
	if len(s.order) > cacheOrderSlack*s.max {
		t.Fatalf("order index holds %d keys for %d live entries (cap %d): it grows on every expire-and-refill cycle", len(s.order), len(s.entries), s.max)
	}
}

// fakeRedis is the smallest redis.Client that can back the Redis cache path:
// only Get and Set are implemented; the embedded nil Cmdable covers the rest of
// the interface and would panic if the code under test reached for it.
type fakeRedis struct {
	redigo.Cmdable
	mu    sync.Mutex
	store map[string][]byte
}

func (f *fakeRedis) Get(_ context.Context, key string) *redigo.StringCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.store[key]
	if !ok {
		return redigo.NewStringResult("", redigo.Nil)
	}
	return redigo.NewStringResult(string(v), nil)
}

func (f *fakeRedis) Set(_ context.Context, key string, value any, _ time.Duration) *redigo.StatusCmd {
	b, ok := value.([]byte)
	if !ok {
		return redigo.NewStatusResult("", errors.New("fakeRedis: value is not []byte"))
	}
	f.mu.Lock()
	f.store[key] = b
	f.mu.Unlock()
	return redigo.NewStatusResult("OK", nil)
}

func (f *fakeRedis) Subscribe(context.Context, ...string) *redigo.PubSub { return nil }

func (f *fakeRedis) Close() error { return nil }

func TestRedisCacheKeysAreNamespacedPerRoute(t *testing.T) {
	shared := &fakeRedis{store: make(map[string][]byte)}
	build := func(route string) http.Handler {
		f := NewFactory(shared, nil, nil, nil, t.TempDir())
		origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("served by " + route))
		})
		return buildCacheMW(t, f, map[string]string{"storage": "redis", "ttl_seconds": "60"}, route, origin)
	}
	a, b := build("route-a"), build("route-b")

	serve(a, hostReq("shop.example", "/catalog"))
	got := serve(b, hostReq("shop.example", "/catalog")).Body.String()
	if got != "served by route-b" {
		t.Fatalf("route B served %q from the shared Redis: keys are not namespaced per route", got)
	}
}
