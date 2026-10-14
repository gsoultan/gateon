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
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
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
//
// The balancer asks it about a backend on every response it records, so a
// prediction is bounded: it waits for and runs the model for at most
// predictBudget in all, and a model still running then is stopped. A model
// stopped that way answers nothing for restartCooldown, then is started
// again from the compiled module.
type WasmTransformerPredictor struct {
	runtime wazero.Runtime
	module  wazero.CompiledModule
	slot    chan struct{} // one prediction at a time; held while the instance is used

	// Owned by whoever holds slot.
	instance  api.Module
	predict   api.Function
	inputPtr  api.Function
	stoppedAt time.Time

	restarting atomic.Bool // a background restart is in flight

	budget time.Duration    // predictBudget; a field so tests can shorten it
	now    func() time.Time // injectable for tests
}

// predictBudget is the longest one prediction may take, waiting included. The
// built-in forecast answers in well under a microsecond; a custom model that
// needs longer than this on every response is too slow to sit on the
// response path, and is refused at load by the probe.
const predictBudget = 10 * time.Millisecond

// restartCooldown is how long a model stopped for overrunning its budget
// stays stopped. A model that hangs every time costs one stalled prediction
// per cooldown rather than one per response.
const restartCooldown = 30 * time.Second

// startBudget bounds a background restart, _initialize included.
const startBudget = 5 * time.Second

// ErrModelUnavailable is returned while a custom model is busy past the
// budget, or stopped and waiting out restartCooldown. The balancer prices
// the backend without the model's weight.
var ErrModelUnavailable = errors.New("the traffic model did not answer within its budget")

// NewWasmTransformerPredictor loads a WASM traffic model and asks it for one
// prediction, so a model that cannot answer is refused here rather than
// failing on every response.
//
// A model must stay running after it starts. A Go WASI *command* does not: its
// _start runs main and exits when main returns, and the module is closed with
// it. That is what `make models` used to build, so a custom model built the
// documented way loaded without error, was reported as running, and failed
// every prediction after -- the balancer quietly used its own average instead.
// Build a *reactor* (-buildmode=c-shared), whose _initialize sets the runtime
// up and returns; it is run here, as a command's _start still is.
func NewWasmTransformerPredictor(ctx context.Context, wasmBytes []byte) (*WasmTransformerPredictor, error) {
	if len(wasmBytes) == 0 {
		return nil, errors.New("wasm bytes are empty")
	}

	// CloseOnContextDone lets a prediction's deadline stop a model that
	// never returns; without it the guest ignores the context.
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	m, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("failed to compile wasm module: %w", err)
	}

	p := &WasmTransformerPredictor{
		runtime: r,
		module:  m,
		slot:    make(chan struct{}, 1),
		budget:  predictBudget,
		now:     time.Now,
	}
	if err := p.start(ctx); err != nil {
		_ = r.Close(ctx)
		return nil, err
	}
	if err := p.probe(ctx); err != nil {
		_ = r.Close(ctx)
		return nil, err
	}
	return p, nil
}

// probe asks a freshly loaded model for one prediction.
func (p *WasmTransformerPredictor) probe(ctx context.Context) error {
	if _, err := p.Predict(ctx, []float64{1, 1}); err != nil {
		if p.instance.IsClosed() {
			return fmt.Errorf("the model exited as soon as it started, so it can never answer "+
				"(a WASI command; build it as a reactor with -buildmode=c-shared): %w", err)
		}
		return fmt.Errorf("the model did not answer a test prediction: %w", err)
	}
	return nil
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

// start instantiates the compiled module and installs it. The caller owns p
// exclusively.
func (p *WasmTransformerPredictor) start(ctx context.Context) error {
	mod, err := p.instantiate(ctx)
	if err != nil {
		return err
	}
	p.install(mod)
	return nil
}

func (p *WasmTransformerPredictor) instantiate(ctx context.Context) (api.Module, error) {
	mod, err := p.runtime.InstantiateModule(ctx, p.module,
		wazero.NewModuleConfig().WithStartFunctions("_initialize", "_start"))
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate module: %w", err)
	}
	return mod, nil
}

// install makes mod the instance predictions use. The caller holds slot, or
// owns p exclusively.
func (p *WasmTransformerPredictor) install(mod api.Module) {
	p.instance = mod
	p.predict = mod.ExportedFunction("predict")
	p.inputPtr = mod.ExportedFunction("get_input_ptr")
}

// Predict asks the model for a spike score. It returns ErrModelUnavailable,
// rather than waiting, once predictBudget has passed.
func (p *WasmTransformerPredictor) Predict(ctx context.Context, input []float64) (float64, error) {
	ctx, cancel := context.WithTimeout(ctx, p.budget)
	defer cancel()
	select {
	case p.slot <- struct{}{}:
	case <-ctx.Done():
		return 0, ErrModelUnavailable
	}
	defer func() { <-p.slot }()

	if err := p.ready(ctx); err != nil {
		return 0, err
	}
	v, err := p.call(ctx, input)
	if err != nil && ctx.Err() != nil {
		// The deadline closed the instance mid-call.
		p.stoppedAt = p.now()
		logger.L.LogWarn("custom AI traffic model overran its budget and was stopped",
			"budget", p.budget, "restart_after", restartCooldown)
		return 0, ErrModelUnavailable
	}
	return v, err
}

// ready reports whether the instance can answer. One the deadline closed is
// restarted once restartCooldown has passed -- in the background, because a
// Go model's _initialize sets up a whole runtime and must not be paid for on
// a response. A model that exited on its own is never restarted: probe
// refuses one at load, and stoppedAt is zero until the first overrun.
func (p *WasmTransformerPredictor) ready(ctx context.Context) error {
	if !p.instance.IsClosed() {
		return nil
	}
	if !p.stoppedAt.IsZero() && p.now().Sub(p.stoppedAt) >= restartCooldown &&
		p.restarting.CompareAndSwap(false, true) {
		p.stoppedAt = p.now() // a restart that fails waits out another cooldown
		// Detached from the prediction's deadline, which is about to fire.
		go p.restart(context.WithoutCancel(ctx))
	}
	return ErrModelUnavailable
}

// restart starts a fresh instance and installs it. It runs outside slot, so
// predictions keep being refused quickly rather than waiting on it, and it
// ends within startBudget, or as soon as Close closes the runtime.
func (p *WasmTransformerPredictor) restart(ctx context.Context) {
	defer p.restarting.Store(false)
	ctx, cancel := context.WithTimeout(ctx, startBudget)
	defer cancel()
	mod, err := p.instantiate(ctx)
	if err != nil {
		logger.L.LogWarn("custom AI traffic model could not be restarted", "error", err)
		return
	}
	p.slot <- struct{}{}
	p.install(mod)
	<-p.slot
}

func (p *WasmTransformerPredictor) call(ctx context.Context, input []float64) (float64, error) {
	if p.predict == nil {
		return 0, errors.New("wasm module does not export 'predict' function")
	}
	if p.inputPtr == nil {
		return 0, errors.New("wasm module does not export 'get_input_ptr'")
	}

	// Get pointer to input buffer
	res, err := p.inputPtr.Call(ctx)
	if err != nil || len(res) == 0 {
		return 0, fmt.Errorf("failed to get input pointer: %w", err)
	}
	ptr := uint32(res[0]) //nosec G115

	mem := p.instance.Memory()
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
	results, err := p.predict.Call(ctx, uint64(len(input)))
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

// ActiveModel names the installed traffic predictor for the dashboard: which
// model is answering, not merely that one is installed.
func ActiveModel() string {
	switch GlobalPredictor().(type) {
	case nil:
		return "Not loaded"
	case *NativePredictor:
		return "Built-in forecast"
	case *WasmTransformerPredictor:
		return "Custom WASM model"
	default:
		return "Custom model"
	}
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
