// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding

package api

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// OPEN: every inter-arrival-time signal is dead in production, and the one
// check that uses it would, once alive, report ordinary polling pages as
// threats. Fixing the first without deciding the second trades a silent check
// for a noisy one. Run with: go test -tags openfinding -run RequestTiming ./internal/api/

const regularIntervals = "regular request intervals"

// TestRequestTimingReachesTheDetectorFromStoredTraces: a client on a fixed
// 2-second timer, recorded and read back the way detectAnomalies reads it.
// GetTracesFiltered walks the store newest-first (iter.Last, iter.Prev), and
// Analyze computes each interval as this trace minus the previous one, keeping
// only positive values -- so for every client every interval is negative and
// dropped. IATCount stays 0: analyzeBehavior's regularity check and the Neural
// Sentinel's two IAT features never see a single interval.
func TestRequestTimingReachesTheDetectorFromStoredTraces(t *testing.T) {
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "traces.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	const poller = "10.44.0.7"
	recordPolling(poller, "/api/items", 2*time.Second, 30)
	telemetry.FlushTraces()

	for _, a := range (&ApiService{}).detectAnomalies(t.Context(), nil) {
		if a.GetSource() == poller && strings.Contains(a.GetDescription(), regularIntervals) {
			return
		}
	}
	traces := telemetry.GetTracesFiltered(t.Context(), 1000, true)
	data := &DiagnosticData{Traces: traces}
	NewAnomalyAnalysisEngine(nil, nil).Analyze(t.Context(), data)
	st := data.IPStats[poller]
	if st == nil {
		t.Fatalf("the poller's traces did not come back from the store")
	}
	t.Errorf("30 requests on a fixed 2s timer were read back from the store and %d inter-arrival intervals "+
		"were measured (first trace read: %s, last: %s)", st.IATCount,
		traces[0].Timestamp.Format(time.TimeOnly), traces[len(traces)-1].Timestamp.Format(time.TimeOnly))
}

// TestRequestTimingAloneDoesNotMakeAPollingPageAThreat: what the regularity
// check does once it can see intervals (traces in time order, as every unit
// test feeds them). A dashboard page polling its status endpoint every five
// seconds is a browser doing what it was written to do; "CV < 0.05" is +60 on
// its own, past the default threshold of 30, and the page is filed as a
// security threat on every pass.
func TestRequestTimingAloneDoesNotMakeAPollingPageAThreat(t *testing.T) {
	const page = "10.44.0.8"
	data := &DiagnosticData{}
	start := time.Now().Add(-5 * time.Minute)
	for i := range 40 {
		data.Traces = append(data.Traces, trace(page, "/api/status", "200", 15,
			start.Add(time.Duration(i)*5*time.Second)))
	}
	for _, a := range NewAnomalyAnalysisEngine(nil, nil).Analyze(t.Context(), data) {
		if a.GetSource() == page && strings.Contains(a.GetDescription(), regularIntervals) {
			t.Errorf("a page polling /api/status every 5s was reported: %s (%s, score %.0f)",
				a.GetDescription(), a.GetSeverity(), a.GetScore())
		}
	}
}

// recordPolling records n successful requests from ip to path, gap apart,
// ending a minute ago.
func recordPolling(ip, path string, gap time.Duration, n int) {
	start := time.Now().Add(-time.Minute - time.Duration(n)*gap)
	for i := range n {
		telemetry.RecordTrace(fmt.Sprintf("poll-%s-%02d", ip, i), "GET "+path, "rt-poll", "svc-poll",
			12, start.Add(time.Duration(i)*gap), "200", path, ip, "", "", "poller/1.0",
			http.MethodGet, "", path, "", "", nil, nil, "", 100, 0, 0, 0, 0)
	}
}

var _ = gateonv1.Anomaly{}
