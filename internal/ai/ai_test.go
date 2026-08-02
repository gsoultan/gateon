// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package ai_test

import (
	"testing"

	"github.com/gsoultan/gateon/internal/ai"
)

func TestPredictorStrategy_Select(t *testing.T) {
	strategy := ai.NewPredictorStrategy()

	urls := []string{
		"10.0.0.1:80",
		"10.0.0.2:80",
	}

	// First select should pick first one or round robin
	selected := strategy.PredictBest(urls)
	if selected == "" {
		t.Fatal("Expected target, got empty string")
	}

	// Update some latency data
	strategy.RecordLatency("10.0.0.1:80", 0.01)
	strategy.RecordLatency("10.0.0.2:80", 0.05)

	// Since 10.0.0.1 is faster, it should be prioritized by the "predictive" logic
	selected = strategy.PredictBest(urls)
	if selected != "10.0.0.1:80" {
		t.Errorf("Expected 10.0.0.1:80, got %s", selected)
	}
}

func TestReinforcementLearningLimiter(t *testing.T) {
	// Mock ebpf manager
	limiter := ai.NewReinforcementLearningLimiter(nil)

	// Feedback for high score threat
	limiter.ProcessFeedback("1.2.3.4", 90)

	// Verify state was updated (using exported methods if any, or internal via alias)
	// Since ai_test can't see internal fields, we just check it doesn't panic.
	limiter.ProcessFeedback("1.2.3.5", 10)
}
