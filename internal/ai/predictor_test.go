// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package ai

import (
	"context"
	"testing"
)

func TestPredictor_Accuracy(t *testing.T) {
	ctx := context.Background()
	if err := InitGlobalPredictor(ctx, DefaultModelWasm); err != nil {
		t.Fatalf("failed to init global predictor: %v", err)
	}
	defer GlobalPredictor.Close(ctx)

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
			score, err := GlobalPredictor.Predict(ctx, tc.input)
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
	defer GlobalPredictor.Close(ctx)

	input := []float64{100, 100, 100, 100, 500}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GlobalPredictor.Predict(ctx, input)
	}
}
