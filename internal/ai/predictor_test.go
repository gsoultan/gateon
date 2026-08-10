// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package ai

import (
	"context"
	"sync"
	"testing"
)

func TestPredictor_Accuracy(t *testing.T) {
	ctx := context.Background()
	if err := InitGlobalPredictor(ctx, DefaultModelWasm); err != nil {
		t.Fatalf("failed to init global predictor: %v", err)
	}
	defer func() { _ = GlobalPredictor().Close(ctx) }()

	tests := []struct {
		name     string
		input    []float64
		minScore float64
		maxScore float64
	}{
		{
			name:     "Flat Traffic",
			input:    []float64{100, 100, 100, 100, 100},
			minScore: 0,
			maxScore: 0.1,
		},
		{
			name:     "Steady Increase",
			input:    []float64{100, 110, 120, 130, 140},
			minScore: 0,
			maxScore: 0.2,
		},
		{
			name:     "Sharp Spike",
			input:    []float64{100, 100, 100, 100, 500},
			minScore: 0.8,
			maxScore: 1.0,
		},
		{
			name:     "Trend then Spike",
			input:    []float64{100, 110, 120, 130, 400},
			minScore: 0.7,
			maxScore: 1.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score, err := GlobalPredictor().Predict(ctx, tc.input)
			if err != nil {
				t.Fatalf("prediction failed: %v", err)
			}
			if score < tc.minScore || score > tc.maxScore {
				t.Errorf("%s: expected score in [%v, %v], got %v", tc.name, tc.minScore, tc.maxScore, score)
			}
		})
	}
}

func BenchmarkPredictor(b *testing.B) {
	ctx := context.Background()
	if err := InitGlobalPredictor(ctx, DefaultModelWasm); err != nil {
		b.Fatalf("failed to init global predictor: %v", err)
	}
	defer func() { _ = GlobalPredictor().Close(ctx) }()

	input := []float64{100, 100, 100, 100, 500}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GlobalPredictor().Predict(ctx, input)
	}
}

// TestModelSelectionUsesContentNotLength covers the silent-fallback bug: model
// selection compared byte lengths, so a custom model that happened to be the
// same size as the embedded default was discarded and replaced by the native
// Holt-Winters path. The operator saw "predictive AI enabled" while running a
// different model than the one they shipped, with no diagnostic anywhere.
func TestModelSelectionUsesContentNotLength(t *testing.T) {
	if !isDefaultModel(DefaultModelWasm) {
		t.Fatal("the embedded default model must be recognised as the default")
	}

	// Same length, different content — the exact case the length check missed.
	impostor := make([]byte, len(DefaultModelWasm))
	copy(impostor, DefaultModelWasm)
	impostor[len(impostor)-1] ^= 0xFF

	if isDefaultModel(impostor) {
		t.Error("a same-length but different model was mistaken for the default; " +
			"a custom model would be silently discarded")
	}
	if isDefaultModel([]byte("short")) {
		t.Error("a differently-sized model was mistaken for the default")
	}
}

// TestGlobalPredictorIsSafeForConcurrentReads exercises the accessor under the
// race detector: it is read from the proxy load-balancer path, the diagnostics
// API and the metrics snapshot while startup installs it.
func TestGlobalPredictorIsSafeForConcurrentReads(t *testing.T) {
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(8)
	for range 4 {
		go func() {
			defer wg.Done()
			for range 50 {
				_ = InitGlobalPredictor(ctx, DefaultModelWasm)
			}
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				if p := GlobalPredictor(); p != nil {
					_, _ = p.Predict(ctx, []float64{1, 2, 3})
				}
			}
		}()
	}
	wg.Wait()
}
