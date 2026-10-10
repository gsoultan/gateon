// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

// rebuilds is how many times these tests build a route's WASM middleware:
// one invalidation each, as a configuration change or the route-problem
// report causes.
const rebuilds = 20

// collectUntil runs the collector until cond holds -- a dropped middleware's
// guest is released by a cleanup, which runs after a collection -- or fails
// after a deadline no healthy runner reaches.
func collectUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not reached after collecting for 10s", what)
		}
		runtime.GC()
		runtime.Gosched()
	}
}

// build builds the middleware around a backend that echoes whether the guest
// ran, failing the test on an error.
func build(t *testing.T, c *wasmCache, routeID string) http.Handler {
	t.Helper()
	mw, err := c.middleware(t.Context(), namedGuest, routeID)
	if err != nil {
		t.Fatalf("build for %s: %v", routeID, err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Guest-Ran", r.Header.Get("X-Wasm"))
	}))
}

// TestWasmRebuildsShareOneCompiledModule: every rebuild of a route compiled
// its module into a new runtime that nothing closed. Rebuilt any number of
// times, a route's module is compiled once.
func TestWasmRebuildsShareOneCompiledModule(t *testing.T) {
	c := newWasmCache()
	var last http.Handler
	for range rebuilds {
		last = build(t, c, "route-a")
	}
	if got := c.compiles.Load(); got != 1 {
		t.Errorf("%d rebuilds compiled %d runtimes, want 1", rebuilds, got)
	}
	if inUse, idle := c.held(); inUse+idle != 1 {
		t.Errorf("%d rebuilds hold %d runtimes in use and %d idle, want 1 in all", rebuilds, inUse, idle)
	}
	rec := httptest.NewRecorder()
	last.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get("X-Guest-Ran") != "ran" {
		t.Error("the shared module did not run for a request")
	}
}

// TestWasmModulesHeldStayBounded: a guest no chain holds any more is closed
// once more than maxIdleWasmModules are idle, so building and dropping many --
// a route whose module changes, or many routes over time -- holds a bounded
// number, and every one compiled and let go is closed.
func TestWasmModulesHeldStayBounded(t *testing.T) {
	c := newWasmCache()
	for i := range rebuilds {
		build(t, c, fmt.Sprintf("route-%d", i))
	}
	collectUntil(t, "dropped guests closed", func() bool {
		return c.closes.Load() >= rebuilds-maxIdleWasmModules
	})
	inUse, idle := c.held()
	if inUse != 0 || idle > maxIdleWasmModules {
		t.Errorf("after dropping every middleware: %d in use and %d idle, want 0 and at most %d", inUse, idle, maxIdleWasmModules)
	}
	if open := c.compiles.Load() - c.closes.Load(); open != uint64(idle) {
		t.Errorf("%d runtimes compiled and not closed, but %d held: a runtime was lost without closing", open, idle)
	}
}

// TestWasmGuestInUseIsNeverClosed: eviction closes idle guests only. A chain
// still serving keeps its guest, however many others are built and dropped
// around it.
func TestWasmGuestInUseIsNeverClosed(t *testing.T) {
	c := newWasmCache()
	live := build(t, c, "kept")
	for i := range rebuilds {
		build(t, c, fmt.Sprintf("dropped-%d", i))
	}
	collectUntil(t, "dropped guests closed", func() bool {
		return c.closes.Load() >= rebuilds-maxIdleWasmModules
	})
	if inUse, _ := c.held(); inUse != 1 {
		t.Errorf("%d guests in use, want the live chain's 1", inUse)
	}
	rec := httptest.NewRecorder()
	live.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get("X-Guest-Ran") != "ran" {
		t.Error("a chain still in use lost its guest")
	}
	runtime.KeepAlive(live)
}

// TestCloseWasmModulesClosesEveryGuest is shutdown: every runtime compiled is
// closed, in use or idle, and nothing builds afterwards.
func TestCloseWasmModulesClosesEveryGuest(t *testing.T) {
	c := newWasmCache()
	live := build(t, c, "in-use")
	build(t, c, "dropped")
	c.closeAll(t.Context())
	if compiled, closed := c.compiles.Load(), c.closes.Load(); compiled != 2 || closed != 2 {
		t.Errorf("compiled %d, closed %d; want 2 and 2", compiled, closed)
	}
	if _, err := c.middleware(t.Context(), namedGuest, "late"); !errors.Is(err, errWasmClosed) {
		t.Errorf("a build after shutdown: %v, want errWasmClosed", err)
	}
	runtime.KeepAlive(live)
}

// TestWasmThatDoesNotCompileIsClosed: a module that does not compile left its
// runtime open, and a refused route retries its build every few seconds.
func TestWasmThatDoesNotCompileIsClosed(t *testing.T) {
	c := newWasmCache()
	if _, err := c.middleware(t.Context(), []byte("not a wasm module"), "r"); err == nil {
		t.Fatal("a blob that is not a module built")
	}
	if compiled, closed := c.compiles.Load(), c.closes.Load(); compiled != 1 || closed != 1 {
		t.Errorf("compiled %d, closed %d; want 1 and 1", compiled, closed)
	}
	if inUse, idle := c.held(); inUse+idle != 0 {
		t.Errorf("a failed build is held: %d in use, %d idle", inUse, idle)
	}
}

// TestWasmGuestSharedWithALiveChainStaysInUse: a rebuild shares its route's
// guest with the chain it replaces, and with the report's throwaway build.
// Those builds being dropped must not idle -- and so let eviction close -- the
// guest a live chain still serves from.
func TestWasmGuestSharedWithALiveChainStaysInUse(t *testing.T) {
	c := newWasmCache()
	live := build(t, c, "shared")
	for i := range rebuilds {
		build(t, c, "shared")
		build(t, c, fmt.Sprintf("dropped-%d", i))
	}
	collectUntil(t, "dropped guests closed", func() bool {
		return c.closes.Load() >= rebuilds-maxIdleWasmModules
	})
	if inUse, _ := c.held(); inUse != 1 {
		t.Errorf("%d guests in use, want the live chain's 1", inUse)
	}
	rec := httptest.NewRecorder()
	live.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get("X-Guest-Ran") != "ran" {
		t.Error("a chain still in use lost the guest it shares")
	}
	runtime.KeepAlive(live)
}
