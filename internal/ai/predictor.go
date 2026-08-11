// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ai

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"

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
		_ = r.Close(ctx)
		return nil, fmt.Errorf("failed to compile wasm module: %w", err)
	}

	// Instantiate the module.
	mod, err := r.InstantiateModule(ctx, m, wazero.NewModuleConfig())
	if err != nil {
		_ = r.Close(ctx)
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

// GlobalPredictor is a shared instance of the traffic predictor.
var GlobalPredictor TrafficPredictor

func InitGlobalPredictor(ctx context.Context, wasmBytes []byte) error {
	// If it's the default model, use the native implementation for "super fast" performance.
	// We compare lengths as a simple heuristic.
	if len(wasmBytes) == len(DefaultModelWasm) {
		GlobalPredictor = &NativePredictor{}
		return nil
	}

	p, err := NewWasmTransformerPredictor(ctx, wasmBytes)
	if err != nil {
		return err
	}
	GlobalPredictor = p
	return nil
}
