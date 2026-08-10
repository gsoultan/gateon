// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ai

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed models/default/model.wasm
var DefaultModelWasm []byte

// TrafficPredictor defines the interface for traffic spike prediction.
type TrafficPredictor interface {
	Predict(ctx context.Context, input []float64) (float64, error)
	Close(ctx context.Context) error
}

// WasmTransformerPredictor implements TrafficPredictor using a WASM-based Transformer model.
// Designed for memory efficiency within a 2GB limit.
type WasmTransformerPredictor struct {
	runtime  wazero.Runtime
	module   wazero.CompiledModule
	instance api.Module
	mu       sync.Mutex
}

// NewWasmTransformerPredictor creates a new WASM-based traffic predictor.
func NewWasmTransformerPredictor(ctx context.Context, wasmBytes []byte) (*WasmTransformerPredictor, error) {
	if len(wasmBytes) == 0 {
		return nil, errors.New("wasm bytes are empty")
	}

	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	m, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("failed to compile wasm module: %w", err)
	}

	// Instantiate the module.
	mod, err := r.InstantiateModule(ctx, m, wazero.NewModuleConfig())
	if err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("failed to instantiate module: %w", err)
	}

	return &WasmTransformerPredictor{
		runtime:  r,
		module:   m,
		instance: mod,
	}, nil
}

// NativePredictor is a pure Go implementation of the Holt-Winters spike detection.
// Used as a high-performance fallback and for the default model to avoid WASM runtime overhead.
type NativePredictor struct{}

func (p *NativePredictor) Predict(ctx context.Context, input []float64) (float64, error) {
	if len(input) < 2 {
		return 0, nil
	}

	alpha := 0.5
	beta := 0.3

	level := input[0]
	trend := input[1] - input[0]

	for i := 1; i < len(input)-1; i++ {
		lastLevel := level
		level = alpha*input[i] + (1-alpha)*(level+trend)
		trend = beta*(level-lastLevel) + (1-beta)*trend
	}

	forecast := level + trend
	latest := input[len(input)-1]
	diff := latest - forecast

	if diff <= 0 {
		return 0, nil
	}

	score := diff / (math.Abs(level) + 1.0)
	val := (score - 1.5) * 2.0
	return 1.0 / (1.0 + math.Exp(-val)), nil
}

func (p *NativePredictor) Close(ctx context.Context) error {
	return nil
}

func (p *WasmTransformerPredictor) Predict(ctx context.Context, input []float64) (float64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	mod := p.instance

	predict := mod.ExportedFunction("predict")
	if predict == nil {
		return 0, errors.New("wasm module does not export 'predict' function")
	}

	getInputPtr := mod.ExportedFunction("get_input_ptr")
	if getInputPtr == nil {
		return 0, errors.New("wasm module does not export 'get_input_ptr'")
	}

	// Get pointer to input buffer
	res, err := getInputPtr.Call(ctx)
	if err != nil || len(res) == 0 {
		return 0, fmt.Errorf("failed to get input pointer: %w", err)
	}
	ptr := uint32(res[0]) //nosec G115

	mem := mod.Memory()
	// Limit input to buffer size
	if len(input) > 1024 {
		input = input[:1024]
	}

	for i, v := range input {
		bits := math.Float64bits(v)
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], bits)
		if !mem.Write(ptr+uint32(i*8), b[:]) { //nosec G115
			return 0, errors.New("failed to write to wasm memory")
		}
	}

	// Call prediction: predict(length) -> predicted_value
	results, err := predict.Call(ctx, uint64(len(input)))
	if err != nil || len(results) == 0 {
		return 0, fmt.Errorf("prediction call failed: %w", err)
	}

	return math.Float64frombits(results[0]), nil
}

// Close releases all WASM resources.
func (p *WasmTransformerPredictor) Close(ctx context.Context) error {
	return p.runtime.Close(ctx)
}

// globalPredictor is the shared traffic predictor.
//
// It is behind an atomic rather than a bare package variable because it is
// written by InitGlobalPredictor at startup and read from the proxy's
// load-balancer path, the diagnostics API and the metrics snapshot. A plain
// variable was safe only for as long as nobody ever replaced the model after
// serving began — an invariant that nothing enforced and that any future
// model hot-reload would break into a data race.
var globalPredictor atomic.Pointer[TrafficPredictor]

// GlobalPredictor returns the active traffic predictor, or nil if none is
// installed.
func GlobalPredictor() TrafficPredictor {
	p := globalPredictor.Load()
	if p == nil {
		return nil
	}
	return *p
}

// isDefaultModel reports whether wasmBytes is the embedded default model.
//
// This used to compare lengths. Any custom model that happened to compile to
// the same byte count as the default was silently discarded and replaced by
// the native Holt-Winters path — the operator would see "predictive AI
// enabled" and get a different model than the one they shipped, with no
// diagnostic anywhere. Comparing content digests makes the check mean what it
// says.
func isDefaultModel(wasmBytes []byte) bool {
	if len(wasmBytes) != len(DefaultModelWasm) {
		return false
	}
	return sha256.Sum256(wasmBytes) == sha256.Sum256(DefaultModelWasm)
}

// InitGlobalPredictor installs the traffic predictor.
//
// The default model runs through NativePredictor: it is the same Holt-Winters
// forecast the WASM module implements, without the runtime and the
// cross-boundary copy on every call.
func InitGlobalPredictor(ctx context.Context, wasmBytes []byte) error {
	if isDefaultModel(wasmBytes) {
		var p TrafficPredictor = &NativePredictor{}
		globalPredictor.Store(&p)
		return nil
	}

	wp, err := NewWasmTransformerPredictor(ctx, wasmBytes)
	if err != nil {
		return err
	}
	var p TrafficPredictor = wp
	globalPredictor.Store(&p)
	return nil
}
