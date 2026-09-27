// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"testing"

	"github.com/gsoultan/gateon/internal/ai"
)

// TestDiagnosticsNamesTheModelThatIsAnswering: the TITAN panel said "Running
// (WASM)" whenever any predictor was installed. The built-in model is served
// by the native forecast and never runs as WASM at all.
func TestDiagnosticsNamesTheModelThatIsAnswering(t *testing.T) {
	ctx := context.Background()
	if err := ai.InitGlobalPredictor(ctx, ai.DefaultModelWasm); err != nil {
		t.Fatalf("install the built-in model: %v", err)
	}
	titan := (&ApiService{}).getSystemInfo(ctx).GetTitan()
	if !titan.GetAiPredictorEnabled() {
		t.Error("an installed predictor is reported as off")
	}
	if got := titan.GetAiModelStatus(); got != "Built-in forecast" {
		t.Errorf("model status with the built-in model installed = %q, want %q", got, "Built-in forecast")
	}
}

// TestDiagnosticsReportsPostQuantumKeyExchangeAsTLSDoes: the panel reported
// post-quantum cryptography as enabled unconditionally. What the gateway has is
// Go's default hybrid ML-KEM key exchange in TLS 1.3, which GODEBUG=tlsmlkem=0
// turns off -- and the panel must say so when it is.
func TestDiagnosticsReportsPostQuantumKeyExchangeAsTLSDoes(t *testing.T) {
	ctx := context.Background()
	t.Setenv("GODEBUG", "")
	if !(&ApiService{}).getSystemInfo(ctx).GetTitan().GetPqcEnabled() {
		t.Error("with Go's default key exchanges, post-quantum key exchange is reported as off")
	}
	t.Setenv("GODEBUG", "http2client=0,tlsmlkem=0")
	if (&ApiService{}).getSystemInfo(ctx).GetTitan().GetPqcEnabled() {
		t.Error("with GODEBUG=tlsmlkem=0, post-quantum key exchange is still reported as on")
	}
}
