// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/ai"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/resource"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
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

// TestDiagnosticsCountsTheServicesThePredictorServes: the panel said the
// predictor was ON because it was loaded, which it always is. The forecast is
// only read by HTTP services balanced with ai_predictive (or intelligent), so
// the panel says how many there are -- every spelling the gateway accepts,
// and not a TCP or UDP service, which cannot use it.
func TestDiagnosticsCountsTheServicesThePredictorServes(t *testing.T) {
	ctx := context.Background()
	store := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	for id, svc := range map[string]*gateonv1.Service{
		"snake":       {LoadBalancerPolicy: "ai_predictive"},
		"dashboard":   {LoadBalancerPolicy: "aiPredictive", BackendType: "http"},
		"other-name":  {LoadBalancerPolicy: "intelligent", BackendType: "grpc"},
		"round-robin": {LoadBalancerPolicy: "roundRobin"},
		"tcp":         {LoadBalancerPolicy: "ai_predictive", BackendType: "tcp"},
	} {
		svc.Id = id
		if err := store.Update(ctx, svc); err != nil {
			t.Fatalf("store %s: %v", id, err)
		}
	}
	got := (&ApiService{Services: store}).getSystemInfo(ctx).GetTitan().GetAiPolicyServiceCount()
	if got != 3 {
		t.Errorf("services using the predictor = %d, want 3", got)
	}
}

// TestDiagnosticsGovernorIsNotActiveUntilItRuns: the panel showed STABLE for
// any governor the API was handed, started or not, at any pressure.
func TestDiagnosticsGovernorIsNotActiveUntilItRuns(t *testing.T) {
	ctx := context.Background()
	gov := (&ApiService{Governor: resource.NewGovernor()}).getSystemInfo(ctx).GetTitan().GetGovernor()
	if gov == nil {
		t.Fatal("no governor block for a configured governor")
	}
	if gov.GetActive() || gov.GetSampled() || gov.GetUnderPressure() {
		t.Errorf("a governor never started: %+v; want inactive, unsampled, not under pressure", gov)
	}
	if gov.GetMemoryThresholdPercent() != 80 || gov.GetCpuThresholdPercent() != 90 {
		t.Errorf("thresholds = (%v, %v), want (80, 90)", gov.GetMemoryThresholdPercent(), gov.GetCpuThresholdPercent())
	}
}
