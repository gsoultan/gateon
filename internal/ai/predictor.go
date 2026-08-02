// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package ai

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// TrafficPredictor defines the interface for traffic spike prediction.
type TrafficPredictor interface {
	Predict(ctx context.Context, input []float64) (float64, error)
	Close(ctx context.Context) error
}

// WasmTransformerPredictor implements TrafficPredictor using a WASM-based Transformer model.
// Designed for memory efficiency within a 2GB limit.
type WasmTransformerPredictor struct {
	runtime wazero.Runtime
	module  wazero.CompiledModule
	mu      sync.Mutex
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

	return &WasmTransformerPredictor{
		runtime: r,
		module:  m,
	}, nil
}

// Predict performs inference on the input traffic vector and returns the predicted spike probability.
func (p *WasmTransformerPredictor) Predict(ctx context.Context, input []float64) (float64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Instantiate fresh module for isolation and memory cleanup.
	mod, err := p.runtime.InstantiateModule(ctx, p.module, wazero.NewModuleConfig())
	if err != nil {
		return 0, fmt.Errorf("failed to instantiate module: %w", err)
	}
	defer mod.Close(ctx)

	predict := mod.ExportedFunction("predict")
	if predict == nil {
		return 0, errors.New("wasm module does not export 'predict' function")
	}

	malloc := mod.ExportedFunction("malloc")
	if malloc == nil {
		return 0, errors.New("wasm module does not export 'malloc'")
	}

	// Allocate memory for input floats (8 bytes each)
	size := uint64(len(input) * 8)
	res, err := malloc.Call(ctx, size)
	if err != nil || len(res) == 0 {
		return 0, fmt.Errorf("memory allocation failed: %w", err)
	}
	ptr := uint32(res[0])

	mem := mod.Memory()
	for i, v := range input {
		bits := math.Float64bits(v)
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, bits)
		if !mem.Write(ptr+uint32(i*8), b) {
			return 0, errors.New("failed to write to wasm memory")
		}
	}

	// Call prediction: predict(ptr, length) -> predicted_value
	results, err := predict.Call(ctx, uint64(ptr), uint64(len(input)))
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

// InitGlobalPredictor initializes the global predictor with the provided WASM bytes.
func InitGlobalPredictor(ctx context.Context, wasmBytes []byte) error {
	p, err := NewWasmTransformerPredictor(ctx, wasmBytes)
	if err != nil {
		return err
	}
	GlobalPredictor = p
	return nil
}
