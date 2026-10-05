// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"container/list"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// wasmMiddleware is one built WASM middleware. Its guest is shared: every
// build of a route's middleware with the same module serves from one compiled
// module, held while any middleware built on it is reachable.
type wasmMiddleware struct {
	guest *wasmModule
	// instance configures the per-request instance. The empty name is
	// deliberate: without WithName an instance takes the module's own name,
	// wazero holds only one live instance per name in a runtime, and every
	// request keeps its instance until the rest of the chain returns -- so
	// while one request was in flight, every concurrent one failed to
	// instantiate and reached the backend without the guest having run. An
	// anonymous instance can exist any number of times.
	instance wazero.ModuleConfig
}

// wasmKey is what makes two builds share a compiled guest: the module, and
// the route, because the host functions a runtime exports file the threats
// its guest records under the route it was built for.
type wasmKey struct {
	blob    [sha256.Size]byte
	routeID string
}

// wasmModule is one compiled guest and the runtime that owns it.
type wasmModule struct {
	key     wasmKey
	runtime wazero.Runtime
	module  wazero.CompiledModule
	// refs counts the built middlewares still reachable that serve from this
	// module, and idle is its place in the idle list while refs is 0. Both are
	// guarded by the cache's mu.
	refs int
	idle *list.Element
}

// maxIdleWasmModules bounds the compiled guests kept with no middleware
// built on them. Each is the compiled code of one module (megabytes for a
// toolchain-built guest), kept so that the rebuild which follows a route
// invalidation, and the route-problem report's own build (ADR 0063), find it
// compiled rather than compiling again; beyond the bound the least recently
// idled is closed. A guest a reachable middleware serves from is never
// closed, so the modules held are the distinct (module, route) pairs the
// live chains use -- one per configured WASM middleware per route -- plus at
// most this many.
const maxIdleWasmModules = 4

// wasmCache shares compiled guests between builds, and closes them.
//
// Building a WASM middleware compiled its module into a new runtime that
// nothing closed. Every rebuild of the route -- each invalidation, each
// configuration change, and the route-problem report, which builds every
// route again -- compiled it again: a 2 MB module took 370 ms of CPU and 25 MB
// of allocation per build, and the compiled code, mapped outside the Go heap
// where the collector does not see it, waited for a collection and a
// finalizer to be unmapped.
type wasmCache struct {
	mu     sync.Mutex
	byKey  map[wasmKey]*wasmModule
	idle   list.List // of *wasmModule, most recently idled at the front
	closed bool
	// compiles and closes count runtimes created and closed.
	compiles, closes atomic.Uint64
}

func newWasmCache() *wasmCache {
	return &wasmCache{byKey: make(map[wasmKey]*wasmModule)}
}

// wasmModules is the process's compiled guests.
var wasmModules = newWasmCache()

// errWasmClosed refuses a build after CloseWasmModules.
var errWasmClosed = errors.New("wasm runtime is shut down")

// CloseWasmModules closes every compiled guest, in use or idle. It is for
// shutdown, after the listeners have drained: a request still in a WASM
// middleware afterwards finds its guest closed.
func CloseWasmModules(ctx context.Context) {
	wasmModules.closeAll(ctx)
}

// Wasm builds the middleware for one route: routeID is what the threats its
// guest records are filed under.
func Wasm(ctx context.Context, blob []byte, routeID string) (kind.Middleware, error) {
	return wasmModules.middleware(ctx, blob, routeID)
}

func (c *wasmCache) middleware(ctx context.Context, blob []byte, routeID string) (kind.Middleware, error) {
	if len(blob) == 0 {
		return nil, errors.New("wasm blob is empty")
	}
	guest, err := c.acquire(ctx, wasmKey{blob: sha256.Sum256(blob), routeID: routeID}, blob)
	if err != nil {
		return nil, err
	}
	mw := &wasmMiddleware{guest: guest, instance: wazero.NewModuleConfig().WithName("")}
	// The guest is released when the middleware is unreachable: when the
	// chain holding it has been replaced or dropped and the last request in
	// it has returned. Nothing else knows when that is -- a chain is a
	// closure, cached, swapped, and built and thrown away by the report.
	runtime.AddCleanup(mw, c.release, guest)
	return mw.wrap, nil
}

// wrap is the middleware. The guest is closed only once mw is unreachable,
// so mw is kept alive until the request has left it.
func (mw *wasmMiddleware) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer runtime.KeepAlive(mw)
		ctx := context.WithValue(r.Context(), wasmRequestContextKey, r)
		mod, err := mw.guest.runtime.InstantiateModule(ctx, mw.guest.module, mw.instance)
		if err != nil {
			logger.L.LogError("failed to instantiate wasm module for request", "error", err)
			next.ServeHTTP(w, r)
			return
		}
		defer mod.Close(ctx)

		handle := mod.ExportedFunction("handle")
		if handle != nil {
			_, err := handle.Call(ctx)
			if err != nil {
				logger.L.LogError("failed to call wasm handle function", "error", err)
			}
		}

		next.ServeHTTP(w, r)
	})
}

// acquire returns the compiled guest for key, compiling it when no build
// holds or keeps it. Compiled outside the lock, which is held for map work
// only: two first builds of one module at once each compile, and the second
// to finish closes its own and takes the first's.
func (c *wasmCache) acquire(ctx context.Context, key wasmKey, blob []byte) (*wasmModule, error) {
	if m, err := c.take(key); m != nil || err != nil {
		return m, err
	}
	m, err := c.compile(ctx, key, blob)
	if err != nil {
		return nil, err
	}
	kept, err := c.insert(m)
	if kept != m {
		c.closeRuntime(ctx, m)
	}
	return kept, err
}

// take refs the guest cached under key, if there is one.
func (c *wasmCache) take(key wasmKey) (*wasmModule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errWasmClosed
	}
	m, ok := c.byKey[key]
	if !ok {
		return nil, nil
	}
	c.refLocked(m)
	return m, nil
}

// insert caches m with one ref, or refs the guest another build cached first
// and returns that one instead.
func (c *wasmCache) insert(m *wasmModule) (*wasmModule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errWasmClosed
	}
	if prev, ok := c.byKey[m.key]; ok {
		c.refLocked(prev)
		return prev, nil
	}
	c.byKey[m.key] = m
	m.refs = 1
	return m, nil
}

func (c *wasmCache) refLocked(m *wasmModule) {
	if m.idle != nil {
		c.idle.Remove(m.idle)
		m.idle = nil
	}
	m.refs++
}

// release drops one middleware's ref. A guest no middleware holds is kept
// idle, and the oldest idle beyond maxIdleWasmModules is closed. Run by the
// runtime's cleanup goroutine.
func (c *wasmCache) release(m *wasmModule) {
	c.mu.Lock()
	if c.closed || m.refs == 0 {
		c.mu.Unlock()
		return
	}
	m.refs--
	if m.refs > 0 {
		c.mu.Unlock()
		return
	}
	m.idle = c.idle.PushFront(m)
	var evicted []*wasmModule
	for c.idle.Len() > maxIdleWasmModules {
		oldest, ok := c.idle.Remove(c.idle.Back()).(*wasmModule)
		if !ok {
			break
		}
		oldest.idle = nil
		delete(c.byKey, oldest.key)
		evicted = append(evicted, oldest)
	}
	c.mu.Unlock()
	for _, e := range evicted {
		c.closeRuntime(context.Background(), e)
	}
}

func (c *wasmCache) closeAll(ctx context.Context) {
	c.mu.Lock()
	all := make([]*wasmModule, 0, len(c.byKey))
	for _, m := range c.byKey {
		all = append(all, m)
	}
	clear(c.byKey)
	c.idle.Init()
	c.closed = true
	c.mu.Unlock()
	for _, m := range all {
		c.closeRuntime(ctx, m)
	}
}

// held reports the guests cached: in use, and idle.
func (c *wasmCache) held() (inUse, idle int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byKey) - c.idle.Len(), c.idle.Len()
}

// compile builds a runtime with the host functions for key's route and
// compiles blob in it. A runtime whose module does not compile is closed.
func (c *wasmCache) compile(ctx context.Context, key wasmKey, blob []byte) (*wasmModule, error) {
	r := wazero.NewRuntime(ctx)
	c.compiles.Add(1)
	m := &wasmModule{key: key, runtime: r}
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		c.closeRuntime(ctx, m)
		return nil, fmt.Errorf("failed to instantiate wasi: %w", err)
	}
	if err := registerHostFuncs(ctx, r, key.routeID); err != nil {
		c.closeRuntime(ctx, m)
		return nil, err
	}
	compiled, err := r.CompileModule(ctx, blob)
	if err != nil {
		c.closeRuntime(ctx, m)
		return nil, fmt.Errorf("failed to compile wasm module: %w", err)
	}
	m.module = compiled
	return m, nil
}

func (c *wasmCache) closeRuntime(ctx context.Context, m *wasmModule) {
	c.closes.Add(1)
	if err := m.runtime.Close(ctx); err != nil {
		logger.L.LogWarn("failed to close a wasm runtime", "error", err)
	}
}
// requestFromGuest returns the request the current guest call is serving.
// Absent means the guest called a host function outside a request, so the
// caller returns rather than acting on a zero value.
func requestFromGuest(ctx context.Context) (*http.Request, bool) {
	r, ok := ctx.Value(wasmRequestContextKey).(*http.Request)
	return r, ok
}

// writeGuestString copies s into the guest buffer at ptr, or -- when the
// buffer is too small -- writes nothing and returns the length the guest needs
// to allocate. Either way the return is len(s), which is the ABI three of the
// host functions below share.
func writeGuestString(m api.Module, ptr, capacity uint32, s string) uint32 {
	if uint32(len(s)) > capacity {
		return uint32(len(s))
	}
	m.Memory().Write(ptr, []byte(s))
	return uint32(len(s))
}

// registerHostFuncs installs the "env" module the guest imports. Split out of
// Wasm, and then into three groups, because six host functions each carrying
// its own guard made one function gocognit scored at 31 -- and because the
// read-guard/write-back shape they share is only visible once it is named.
func registerHostFuncs(ctx context.Context, rt wazero.Runtime, routeID string) error {
	b := rt.NewHostModuleBuilder("env")
	b = withHeaderFuncs(b)
	b = withRequestFuncs(b)
	b = withDiagnosticFuncs(b, guestThreats{routeID: routeID})

	if _, err := b.Instantiate(ctx); err != nil {
		return fmt.Errorf("failed to instantiate host module: %w", err)
	}
	return nil
}

// withHeaderFuncs exports the two header accessors. set_header mutates the
// request the rest of the chain will see, so a guest that runs outside a
// request must change nothing at all rather than write into a zero value.
func withHeaderFuncs(b wazero.HostModuleBuilder) wazero.HostModuleBuilder {
	return b.
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, namePtr, nameLen, valPtr, valLen uint32) {
			r, ok := requestFromGuest(ctx)
			if !ok {
				return
			}
			name, _ := m.Memory().Read(namePtr, nameLen)
			val, _ := m.Memory().Read(valPtr, valLen)
			r.Header.Set(string(name), string(val))
		}).Export("set_header").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, namePtr, nameLen, valPtr, valLen uint32) uint32 {
			r, ok := requestFromGuest(ctx)
			if !ok {
				return 0
			}
			name, _ := m.Memory().Read(namePtr, nameLen)
			return writeGuestString(m, valPtr, valLen, r.Header.Get(string(name)))
		}).Export("get_header")
}

// withRequestFuncs exports the read-only request properties.
func withRequestFuncs(b wazero.HostModuleBuilder) wazero.HostModuleBuilder {
	return b.
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, valPtr, valLen uint32) uint32 {
			r, ok := requestFromGuest(ctx)
			if !ok {
				return 0
			}
			return writeGuestString(m, valPtr, valLen, r.Method)
		}).Export("get_method").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, valPtr, valLen uint32) uint32 {
			r, ok := requestFromGuest(ctx)
			if !ok {
				return 0
			}
			url := r.RequestURI
			if url == "" {
				url = r.URL.Path
			}
			return writeGuestString(m, valPtr, valLen, url)
		}).Export("get_url")
}

// withDiagnosticFuncs exports logging and threat reporting.
func withDiagnosticFuncs(b wazero.HostModuleBuilder, threats guestThreats) wazero.HostModuleBuilder {
	return b.
		NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module, msgPtr, msgLen uint32) {
			msg, _ := m.Memory().Read(msgPtr, msgLen)
			logger.L.LogInfo(string(msg), "component", "wasm")
		}).Export("log").
		NewFunctionBuilder().
		WithFunc(threats.record).Export("record_threat")
}

// maxGuestThreatScore is the top of the scale every other threat is scored
// on. A plugin is code the operator installed, not code the operator wrote,
// and its score was taken as given: one record_threat of 1e9 took the client's
// reputation to zero in one call, and cleared by itself the score at which a
// detection nobody refused is escalated towards a block.
const maxGuestThreatScore = 100

// guestThreats records the threats one route's guest reports. Each runtime
// has its own host module, so the route is fixed when the module is built.
type guestThreats struct {
	routeID string
}

// record is the record_threat host function.
//
// What a guest records is Observed (ADR 0059): counted, shown and shipped, and
// held against nobody. The host gives a guest no way to refuse a request --
// handle's result is not read and the request always continues -- so a guest
// that records a threat has let the request through, and a detection the
// gateway let through is not evidence against its client. It used to lower
// the client's reputation by half a score the plugin chose, without limit, so
// one call could get the client refused on every route. If the host ever lets
// a guest refuse, a threat recorded for a request it refused is the one that
// may count.
//
// The source is the client address the gateway resolved, as every other
// threat's is. It was RemoteAddr -- the peer, with its port -- and the route
// came from X-Gateon-Route-ID, a header the client writes.
func (g guestThreats) record(ctx context.Context, m api.Module, typePtr, typeLen, detailsPtr, detailsLen uint32, score float64) {
	r, ok := requestFromGuest(ctx)
	if !ok {
		return
	}
	threatType, _ := m.Memory().Read(typePtr, typeLen)
	details, _ := m.Memory().Read(detailsPtr, detailsLen)

	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		Type:        string(threatType),
		SourceIP:    request.ClientAddr(r),
		Score:       clampGuestScore(score),
		Details:     string(details),
		RouteID:     g.routeID,
		RequestURI:  r.RequestURI,
		ActionTaken: telemetry.ActionDetected,
		Observed:    true,
	}))
}

// clampGuestScore puts a guest's score on the 0..maxGuestThreatScore scale. NaN,
// which compares false with everything and so passes any bound written as a
// comparison, is 0.
func clampGuestScore(score float64) float64 {
	if math.IsNaN(score) || score < 0 {
		return 0
	}
	return min(score, maxGuestThreatScore)
}

type wasmContextKey string

const wasmRequestContextKey wasmContextKey = "wasm_request"
