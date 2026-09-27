// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding

package api

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// OPEN: the header checks never see a header. Run with:
// go test -tags openfinding -run HeaderSignals ./internal/api/
// (The two request-timing findings recorded here are fixed; their tests live
// in request_timing_test.go.)

// TestHeaderSignalsReachTheDetectorFromStoredTraces: checkHeaderConsistency (a
// "Mozilla" client with no Accept-Language is a script wearing a browser's
// name) and the Neural Sentinel's entropy feature both read
// TraceRecord.RequestHeaders, and detectAnomalies reads the store with
// summary=true, whose decoder has no headers field. The unit test for the check
// passes because it hands Analyze headers production never has.
func TestHeaderSignalsReachTheDetectorFromStoredTraces(t *testing.T) {
	openTraceStore(t)

	const script = "10.44.0.9"
	start := time.Now().Add(-2 * time.Minute)
	for i := range 10 {
		telemetry.RecordTrace(fmt.Sprintf("spoof-%02d", i), "GET /", "rt-web", "svc-web", 12,
			start.Add(time.Duration(i)*time.Second), "200", "/", script, "", "",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0", http.MethodGet, "", "/", "", "",
			map[string][]string{"User-Agent": {"Mozilla/5.0"}, "Accept": {"*/*"}}, nil, "", 100, 0, 0, 0, 0)
	}
	telemetry.FlushTraces()

	data := &DiagnosticData{Traces: telemetry.GetTracesFiltered(t.Context(), 1000, true)}
	NewAnomalyAnalysisEngine(nil, nil).Analyze(t.Context(), data)
	if st := data.IPStats[script]; st == nil || st.HeaderAnomaly == 0 {
		var headers string
		if len(data.Traces) > 0 {
			headers = data.Traces[0].RequestHeaders
		}
		t.Errorf("10 requests claiming to be Chrome sent no Accept-Language, and the detector counted no header "+
			"anomaly: the traces it reads carry RequestHeaders %q", headers)
	}
}
