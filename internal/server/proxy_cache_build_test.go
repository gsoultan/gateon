// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// gatedMiddlewareStore holds every Get for one middleware id until released,
// which stands in for a chain build that is slow for any reason: a WAF
// compiling a large rule set, a provider being reached, a file being read.
type gatedMiddlewareStore struct {
	config.MiddlewareStore
	gateID  string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *gatedMiddlewareStore) Get(ctx context.Context, id string) (*gateonv1.Middleware, bool) {
	if id == s.gateID {
		s.once.Do(func() { close(s.entered) })
		<-s.release
	}
	return s.MiddlewareStore.Get(ctx, id)
}

type cacheFixture struct {
	routes *config.RouteRegistry
	mws    *config.MiddlewareRegistry
	cache  *ProxyCache
	gate   *gatedMiddlewareStore
}

// newCacheFixture builds a proxy cache over real registries and one backend,
// with Gets for gateID held until the returned release is called.
func newCacheFixture(t *testing.T, gateID string) (*cacheFixture, func()) {
	t.Helper()
	dir := t.TempDir()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("backend"))
	}))
	t.Cleanup(backend.Close)

	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	if err := services.Update(t.Context(), &gateonv1.Service{
		Id: "svc", Name: "svc", WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	}); err != nil {
		t.Fatalf("service: %v", err)
	}
	f := &cacheFixture{
		routes: config.NewRouteRegistry(filepath.Join(dir, "routes.json")),
		mws:    config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json")),
	}
	f.gate = &gatedMiddlewareStore{
		MiddlewareStore: f.mws, gateID: gateID,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	var once sync.Once
	release := func() { once.Do(func() { close(f.gate.release) }) }
	t.Cleanup(release)
	globals := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	f.cache = NewProxyCache(f.routes, services, f.gate, nil, globals, nil, nil)
	return f, release
}

func (f *cacheFixture) route(t *testing.T, id string, mws ...string) *gateonv1.Route {
	t.Helper()
	rt := &gateonv1.Route{Id: id, Name: id, ServiceId: "svc", Rule: "PathPrefix(`/`)", Middlewares: mws}
	if err := f.routes.Update(t.Context(), rt); err != nil {
		t.Fatalf("route %s: %v", id, err)
	}
	return rt
}

func (f *cacheFixture) headerMiddleware(t *testing.T, id, version string) {
	t.Helper()
	if err := f.mws.Update(t.Context(), &gateonv1.Middleware{
		Id: id, Name: id, Type: "headers", Config: map[string]string{"set_response_X-Version": version},
	}); err != nil {
		t.Fatalf("middleware %s: %v", id, err)
	}
}

func serveThrough(h http.Handler) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil))
	return rec
}

// TestSlowChainBuildDoesNotBlockOtherRoutes holds one route's chain build open
// and asks for another route's.
//
// GetOrCreate built chains while holding the cache-wide write lock, so one
// slow build — an oidc provider that never answered was enough — stalled the
// first request of every other route, and after any invalidation that meant
// every route in the gateway.
func TestSlowChainBuildDoesNotBlockOtherRoutes(t *testing.T) {
	f, _ := newCacheFixture(t, "slow")
	f.headerMiddleware(t, "slow", "v1")
	slow := f.route(t, "slow-route", "slow")
	other := f.route(t, "other-route")

	go f.cache.GetOrCreate(slow)
	<-f.gate.entered

	done := make(chan http.Handler, 1)
	go func() { done <- f.cache.GetOrCreate(other) }()
	select {
	case h := <-done:
		if rec := serveThrough(h); rec.Code != http.StatusOK {
			t.Fatalf("other route: status %d, want 200", rec.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("building one route's chain waited for another route's build to finish")
	}
}

// TestInvalidationDuringABuildIsNeitherBlockedNorLost repoints a route at a
// different middleware while its chain is being built from the old route.
//
// The invalidation must not wait for the build, and the chain the build
// produces from the route as it was must not be cached: the caller handed the
// build the old route, so without a check the route keeps serving the old
// configuration until the next edit.
func TestInvalidationDuringABuildIsNeitherBlockedNorLost(t *testing.T) {
	f, release := newCacheFixture(t, "hdr-v1")
	f.headerMiddleware(t, "hdr-v1", "v1")
	f.headerMiddleware(t, "hdr-v2", "v2")
	old := f.route(t, "versioned", "hdr-v1")

	first := make(chan http.Handler, 1)
	go func() { first <- f.cache.GetOrCreate(old) }()
	<-f.gate.entered

	f.route(t, "versioned", "hdr-v2")
	invalidated := make(chan struct{})
	go func() {
		f.cache.InvalidateRoute(old.Id)
		close(invalidated)
	}()
	select {
	case <-invalidated:
	case <-time.After(5 * time.Second):
		t.Fatal("invalidating a route waited for its in-flight build")
	}

	release()
	<-first
	current, ok := f.routes.Get(t.Context(), old.Id)
	if !ok {
		t.Fatal("route vanished")
	}
	if got := serveThrough(f.cache.GetOrCreate(current)).Header().Get("X-Version"); got != "v2" {
		t.Fatalf("after the edit the route serves X-Version %q, want v2: a chain built from the old route was cached", got)
	}
}

// TestRefusedChainRecoversWithoutAnEdit builds a route whose security
// middleware is missing, then supplies it without an invalidation — the shape
// of a dependency that was briefly unavailable (a provider, a database file
// still downloading) when the chain was first built.
//
// The refusal used to be cached with the chain like any other handler, so the
// route kept answering 503 until someone edited it or restarted the gateway.
func TestRefusedChainRecoversWithoutAnEdit(t *testing.T) {
	f, release := newCacheFixture(t, "")
	release()
	f.cache.refusalRetry = time.Nanosecond
	rt := f.route(t, "late", "late-mw")

	if rec := serveThrough(f.cache.GetOrCreate(rt)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing middleware: status %d, want 503", rec.Code)
	}
	f.headerMiddleware(t, "late-mw", "v1")
	if rec := serveThrough(f.cache.GetOrCreate(rt)); rec.Code != http.StatusOK {
		t.Fatalf("once the middleware exists: status %d, want 200 — the refusal was cached for good", rec.Code)
	}
}

// TestCacheConvergesUnderConcurrentEdits edits routes while readers keep
// fetching and serving them, the way a busy gateway sees a config change, and
// checks every route serves its last configuration once the edits stop. Its
// job is to run the lock-free build path under the race detector; the stale
// interleaving it can produce is too narrow to hit reliably, so
// TestStaleRouteFromTheCallerIsNotCached pins that one deterministically.
func TestCacheConvergesUnderConcurrentEdits(t *testing.T) {
	f, release := newCacheFixture(t, "")
	release()
	const routes, edits = 4, 40
	id := func(i int) string { return "route-" + strconv.Itoa(i) }
	mw := func(i, v int) string { return id(i) + "-v" + strconv.Itoa(v) }
	for i := range routes {
		f.headerMiddleware(t, mw(i, 0), "0")
		f.route(t, id(i), mw(i, 0))
	}

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for r := range 8 {
		readers.Go(func() {
			for n := r; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				if rt, ok := f.routes.Get(context.Background(), id(n%routes)); ok {
					if h := f.cache.GetOrCreate(rt); h != nil {
						serveThrough(h)
					}
				}
			}
		})
	}
	for v := 1; v <= edits; v++ {
		for i := range routes {
			f.headerMiddleware(t, mw(i, v), strconv.Itoa(v))
			f.route(t, id(i), mw(i, v))
			f.cache.InvalidateRoute(id(i))
		}
	}
	close(stop)
	readers.Wait()

	for i := range routes {
		rt, _ := f.routes.Get(t.Context(), id(i))
		if got := serveThrough(f.cache.GetOrCreate(rt)).Header().Get("X-Version"); got != strconv.Itoa(edits) {
			t.Fatalf("%s serves X-Version %q after the edits stopped, want %d", id(i), got, edits)
		}
	}
}

// TestStaleRouteFromTheCallerIsNotCached reproduces the interleaving a request
// hits when it selects a route just before an edit and asks the cache for the
// chain just after the edit's invalidation. The build must compile the route as
// it is stored now: compiling the caller's copy caches the old route under the
// new epoch, and it is then served until the next edit.
func TestStaleRouteFromTheCallerIsNotCached(t *testing.T) {
	f, release := newCacheFixture(t, "")
	release()
	f.headerMiddleware(t, "hdr-v1", "v1")
	f.headerMiddleware(t, "hdr-v2", "v2")
	selected := f.route(t, "versioned", "hdr-v1")

	f.route(t, "versioned", "hdr-v2")
	f.cache.InvalidateRoute(selected.Id)

	if got := serveThrough(f.cache.GetOrCreate(selected)).Header().Get("X-Version"); got != "v2" {
		t.Errorf("the request that raced the edit was served X-Version %q, want v2", got)
	}
	current, _ := f.routes.Get(t.Context(), selected.Id)
	if got := serveThrough(f.cache.GetOrCreate(current)).Header().Get("X-Version"); got != "v2" {
		t.Fatalf("after the edit the route serves X-Version %q, want v2: the stale route was cached", got)
	}
}
