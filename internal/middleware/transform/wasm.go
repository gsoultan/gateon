// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"context"
	"fmt"
	"math"
	"net/http"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type wasmMiddleware struct {
	runtime wazero.Runtime
	module  wazero.CompiledModule
	// instance configures the per-request instance. The empty name is
	// deliberate: without WithName an instance takes the module's own name,
	// wazero holds only one live instance per name in a runtime, and every
	// request keeps its instance until the rest of the chain returns -- so
	// while one request was in flight, every concurrent one failed to
	// instantiate and reached the backend without the guest having run. An
	// anonymous instance can exist any number of times.
	instance wazero.ModuleConfig
}

// Wasm builds the middleware for one route: routeID is what the threats its
// guest records are filed under.
func Wasm(ctx context.Context, blob []byte, routeID string) (kind.Middleware, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("wasm blob is empty")
	}

	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	if err := registerHostFuncs(ctx, r, routeID); err != nil {
		return nil, err
	}

	m, err := r.CompileModule(ctx, blob)
	if err != nil {
		return nil, fmt.Errorf("failed to compile wasm module: %w", err)
	}

	mw := &wasmMiddleware{
		runtime:  r,
		module:   m,
		instance: wazero.NewModuleConfig().WithName(""),
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), wasmRequestContextKey, r)
			mod, err := mw.runtime.InstantiateModule(ctx, mw.module, mw.instance)
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
	}, nil
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
