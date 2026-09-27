// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// TestSystemMetricsReportWhichDetectorsRun: neuralSentinelEnabled and
// graphIntelligenceEnabled were true on every install, including the default
// one, where anomaly detection is off and neither detector runs. The snapshot
// now says what the API's own conditions say, and says off when nothing has
// told it.
func TestSystemMetricsReportWhichDetectorsRun(t *testing.T) {
	seedPublicIP(t)
	t.Cleanup(func() { globalDetectorStatus.Store(nil) })

	for _, tc := range []struct{ neural, graph bool }{{false, false}, {false, true}, {true, true}} {
		SetDetectorStatusProvider(func() (bool, bool) { return tc.neural, tc.graph })
		sm := buildSystemMetrics(map[string]*dto.MetricFamily{})
		if sm.NeuralSentinelEnabled != tc.neural || sm.GraphIntelligenceEnabled != tc.graph {
			t.Errorf("the detectors report (neural %v, graph %v); the snapshot says (%v, %v)",
				tc.neural, tc.graph, sm.NeuralSentinelEnabled, sm.GraphIntelligenceEnabled)
		}
	}

	globalDetectorStatus.Store(nil)
	if sm := buildSystemMetrics(map[string]*dto.MetricFamily{}); sm.NeuralSentinelEnabled || sm.GraphIntelligenceEnabled {
		t.Errorf("with nothing to ask, the snapshot says the detectors run (%v, %v)",
			sm.NeuralSentinelEnabled, sm.GraphIntelligenceEnabled)
	}
}

// seedPublicIP fills the public-address cache, so building the snapshot does
// not go to the network for it.
func seedPublicIP(t *testing.T) {
	t.Helper()
	publicIPCacheMu.Lock()
	prevIP, prevAt := publicIPCache, lastIPFetch
	publicIPCache, lastIPFetch = "192.0.2.1", time.Now()
	publicIPCacheMu.Unlock()
	t.Cleanup(func() {
		publicIPCacheMu.Lock()
		publicIPCache, lastIPFetch = prevIP, prevAt
		publicIPCacheMu.Unlock()
	})
}
