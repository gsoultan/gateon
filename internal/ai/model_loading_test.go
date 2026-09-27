// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ai

import (
	"context"
	"encoding/binary"
	"math"
	"strings"
	"testing"
)

// modelSpec describes a minimal hand-assembled traffic model: the exports a
// model needs, a start function, and a predict that answers a constant.
type modelSpec struct {
	start     string  // "_start" or "_initialize"
	exits     bool    // start calls proc_exit(0), as a Go WASI command's does
	initSets  float64 // value start stores in the global predict answers
	traps     bool    // predict executes unreachable
	noPredict bool    // leave the predict export out
}

// wasmModel assembles spec into a module. predict answers a global that
// starts at 0 and that the start function sets to initSets, so a test can
// tell whether start ran.
func wasmModel(spec modelSpec) []byte {
	section := func(id byte, body ...byte) []byte { return append([]byte{id, byte(len(body))}, body...) }
	name := func(s string) []byte { return append([]byte{byte(len(s))}, s...) }
	f64 := func(v float64) []byte { return binary.LittleEndian.AppendUint64(nil, math.Float64bits(v)) }

	m := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	m = append(m, section(1, 4, // types
		0x60, 0, 0, // 0: () -> ()
		0x60, 1, 0x7f, 1, 0x7c, // 1: (i32) -> f64
		0x60, 0, 1, 0x7f, // 2: () -> i32
		0x60, 1, 0x7f, 0, // 3: (i32) -> ()
	)...)
	imp := append([]byte{1}, name("wasi_snapshot_preview1")...)
	imp = append(append(imp, name("proc_exit")...), 0x00, 3) // func 0
	m = append(m, section(2, imp...)...)
	m = append(m, section(3, 3, 0, 1, 2)...) // funcs 1 start, 2 predict, 3 get_input_ptr
	m = append(m, section(5, 1, 0x00, 1)...) // one page of memory
	glob := append([]byte{1, 0x7c, 0x01, 0x44}, f64(0)...)
	m = append(m, section(6, append(glob, 0x0b)...)...)

	exp := []byte{0}
	add := func(n string, kind, idx byte) { exp[0]++; exp = append(append(exp, name(n)...), kind, idx) }
	add(spec.start, 0x00, 1)
	if !spec.noPredict {
		add("predict", 0x00, 2)
	}
	add("get_input_ptr", 0x00, 3)
	add("memory", 0x02, 0)
	m = append(m, section(7, exp...)...)

	start := append(append([]byte{0x00, 0x44}, f64(spec.initSets)...), 0x24, 0) // global.set 0
	if spec.exits {
		start = append(start, 0x41, 0, 0x10, 0) // proc_exit(0)
	}
	start = append(start, 0x0b)
	predict := []byte{0x00, 0x23, 0, 0x0b} // global.get 0
	if spec.traps {
		predict = []byte{0x00, 0x00, 0x0b}
	}
	ptr := []byte{0x00, 0x41, 0, 0x0b}
	code := []byte{3}
	for _, body := range [][]byte{start, predict, ptr} {
		code = append(append(code, byte(len(body))), body...)
	}
	return append(m, section(10, code...)...)
}

func loadModel(t *testing.T, wasm []byte) (*WasmTransformerPredictor, error) {
	t.Helper()
	p, err := NewWasmTransformerPredictor(context.Background(), wasm)
	if p != nil {
		t.Cleanup(func() { _ = p.Close(context.Background()) })
	}
	return p, err
}

// TestDefaultModelMatchesTheNativePredictor: the built-in model is served by
// NativePredictor on the claim that it is the same forecast as the WASM
// module. The module could not be run at all -- `make models` built a WASI
// command, which exits as soon as it starts -- so the claim was untestable,
// and every custom model built the same way was installed, reported as
// running, and never answered once.
func TestDefaultModelMatchesTheNativePredictor(t *testing.T) {
	wp, err := loadModel(t, DefaultModelWasm)
	if err != nil {
		t.Fatalf("the built-in model does not load as a WASM model: %v", err)
	}
	ctx := context.Background()
	native := &NativePredictor{}
	for _, in := range [][]float64{
		{100, 100, 100, 100, 100},
		{100, 110, 120, 130, 140},
		{100, 100, 100, 100, 500},
		{100, 110, 120, 130, 400},
		{0.02, 0.02, 0.02, 2.0},
		{0.5, 0.5},
		{1},
	} {
		got, err := wp.Predict(ctx, in)
		if err != nil {
			t.Fatalf("WASM predict(%v): %v", in, err)
		}
		want, _ := native.Predict(ctx, in)
		if math.Abs(got-want) > 0.01 {
			t.Errorf("predict(%v): WASM %v, native %v", in, got, want)
		}
	}
}

// TestAModelThatExitsWhenItStartsIsRefused: a model whose start function
// exits -- what every Go WASI command does when main returns -- is closed
// before the first prediction. It must be refused at load, saying how to
// build one that works, not installed as if it were running.
func TestAModelThatExitsWhenItStartsIsRefused(t *testing.T) {
	_, err := loadModel(t, wasmModel(modelSpec{start: "_start", exits: true, initSets: 0.5}))
	if err == nil {
		t.Fatal("a model that exits when it starts was accepted")
	}
	if !strings.Contains(err.Error(), "-buildmode=c-shared") {
		t.Errorf("refusal %q does not say how to build a model that stays running", err)
	}
}

// TestAModelWhoseStartReturnsIsAccepted: a command whose start returns
// without exiting -- wasi-libc's, when main returns 0 -- stays usable and
// must not be refused along with the ones that exit.
func TestAModelWhoseStartReturnsIsAccepted(t *testing.T) {
	p, err := loadModel(t, wasmModel(modelSpec{start: "_start", initSets: 0.5}))
	if err != nil {
		t.Fatalf("a model whose start returns was refused: %v", err)
	}
	if got, err := p.Predict(context.Background(), []float64{1, 2}); err != nil || got != 0.5 {
		t.Fatalf("Predict = %v, %v; want 0.5, nil", got, err)
	}
}

// TestAReactorModelIsInitialised: a reactor -- what -buildmode=c-shared
// builds -- is initialised by _initialize. Nothing called it, and a Go model
// predicts on an uninitialised runtime.
func TestAReactorModelIsInitialised(t *testing.T) {
	p, err := loadModel(t, wasmModel(modelSpec{start: "_initialize", initSets: 0.25}))
	if err != nil {
		t.Fatalf("a reactor model was refused: %v", err)
	}
	if got, err := p.Predict(context.Background(), []float64{1, 2}); err != nil || got != 0.25 {
		t.Fatalf("Predict = %v, %v; want 0.25 (the value _initialize sets), nil", got, err)
	}
}

// TestAModelThatCannotAnswerIsRefused: a model is asked once at load, so one
// that traps or lacks predict is refused where the operator sees it rather
// than failing silently on every response.
func TestAModelThatCannotAnswerIsRefused(t *testing.T) {
	for name, spec := range map[string]modelSpec{
		"predict traps":       {start: "_initialize", traps: true},
		"no predict exported": {start: "_initialize", noPredict: true},
	} {
		if _, err := loadModel(t, wasmModel(spec)); err == nil {
			t.Errorf("%s: model accepted", name)
		}
	}
}
