// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type wasmMiddleware struct {
	runtime wazero.Runtime
	module  wazero.CompiledModule
}

func Wasm(ctx context.Context, blob []byte) (kind.Middleware, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("wasm blob is empty")
	}

	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	if err := registerHostFuncs(ctx, r); err != nil {
		return nil, err
	}

	m, err := r.CompileModule(ctx, blob)
	if err != nil {
		return nil, fmt.Errorf("failed to compile wasm module: %w", err)
	}

	mw := &wasmMiddleware{
		runtime: r,
		module:  m,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), wasmRequestContextKey, r)
			mod, err := mw.runtime.InstantiateModule(ctx, mw.module, wazero.NewModuleConfig())
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
func registerHostFuncs(ctx context.Context, rt wazero.Runtime) error {
	b := rt.NewHostModuleBuilder("env")
	b = withHeaderFuncs(b)
	b = withRequestFuncs(b)
	b = withDiagnosticFuncs(b)

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
func withDiagnosticFuncs(b wazero.HostModuleBuilder) wazero.HostModuleBuilder {
	return b.
		NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module, msgPtr, msgLen uint32) {
			msg, _ := m.Memory().Read(msgPtr, msgLen)
			logger.L.LogInfo(string(msg), "component", "wasm")
		}).Export("log").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, typePtr, typeLen, detailsPtr, detailsLen uint32, score float64) {
			r, ok := requestFromGuest(ctx)
			if !ok {
				return
			}
			threatType, _ := m.Memory().Read(typePtr, typeLen)
			details, _ := m.Memory().Read(detailsPtr, detailsLen)

			telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
				Type:       string(threatType),
				SourceIP:   r.RemoteAddr,
				Score:      score,
				Details:    string(details),
				RouteID:    r.Header.Get("X-Gateon-Route-ID"),
				RequestURI: r.RequestURI,
			}))
		}).Export("record_threat")
}

type wasmContextKey string

const wasmRequestContextKey wasmContextKey = "wasm_request"
