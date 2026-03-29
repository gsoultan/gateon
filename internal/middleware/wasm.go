package middleware

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type wasmMiddleware struct {
	runtime wazero.Runtime
	module  wazero.CompiledModule
	pool    sync.Pool
}

func Wasm(ctx context.Context, blob []byte) (Middleware, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("wasm blob is empty")
	}

	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	// Host functions for the WASM module to interact with the HTTP request.
	_, err := r.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, namePtr, nameLen, valPtr, valLen uint32) {
			r, ok := ctx.Value(wasmRequestContextKey).(*http.Request)
			if !ok {
				return
			}
			name, _ := m.Memory().Read(namePtr, nameLen)
			val, _ := m.Memory().Read(valPtr, valLen)
			r.Header.Set(string(name), string(val))
		}).Export("set_header").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, namePtr, nameLen, valPtr, valLen uint32) uint32 {
			r, ok := ctx.Value(wasmRequestContextKey).(*http.Request)
			if !ok {
				return 0
			}
			name, _ := m.Memory().Read(namePtr, nameLen)
			val := r.Header.Get(string(name))
			if uint32(len(val)) > valLen {
				return uint32(len(val))
			}
			m.Memory().Write(valPtr, []byte(val))
			return uint32(len(val))
		}).Export("get_header").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, msgPtr, msgLen uint32) {
			msg, _ := m.Memory().Read(msgPtr, msgLen)
			logger.L.Info().Str("wasm", "log").Msg(string(msg))
		}).Export("log").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, valPtr, valLen uint32) uint32 {
			r, ok := ctx.Value(wasmRequestContextKey).(*http.Request)
			if !ok {
				return 0
			}
			val := r.Method
			if uint32(len(val)) > valLen {
				return uint32(len(val))
			}
			m.Memory().Write(valPtr, []byte(val))
			return uint32(len(val))
		}).Export("get_method").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, valPtr, valLen uint32) uint32 {
			r, ok := ctx.Value(wasmRequestContextKey).(*http.Request)
			if !ok {
				return 0
			}
			val := r.URL.String()
			if uint32(len(val)) > valLen {
				return uint32(len(val))
			}
			m.Memory().Write(valPtr, []byte(val))
			return uint32(len(val))
		}).Export("get_url").
		Instantiate(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate host module: %w", err)
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
				logger.L.Error().Err(err).Msg("failed to instantiate wasm module for request")
				next.ServeHTTP(w, r)
				return
			}
			defer mod.Close(ctx)

			handle := mod.ExportedFunction("handle")
			if handle != nil {
				_, err := handle.Call(ctx)
				if err != nil {
					logger.L.Error().Err(err).Msg("failed to call wasm handle function")
				}
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

type wasmContextKey string

const wasmRequestContextKey wasmContextKey = "wasm_request"
