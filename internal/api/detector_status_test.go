// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"fmt"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestDetectorStatusSaysWhatRuns: the status the dashboard reads was "on" for
// both detectors whatever the configuration. It is now DetectorStatus, and
// this holds it to the detectors themselves: under each configuration, a
// detector is reported running exactly when it reports the attack it exists
// to find.
func TestDetectorStatusSaysWhatRuns(t *testing.T) {
	configs := map[string]*gateonv1.AnomalyDetectionConfig{
		"no configuration":        nil,
		"anomaly detection off":   {Enabled: false, Sensitivity: 0.5},
		"on, at sensitivity 0":    {Enabled: true, Sensitivity: 0},
		"on, at the default 0.5":  {Enabled: true, Sensitivity: 0.5},
		"on, at the highest, 1.0": {Enabled: true, Sensitivity: 1},
	}
	for name, cfg := range configs {
		t.Run(name, func(t *testing.T) {
			freshGraph(t)
			neural, graph := DetectorStatus(cfg)
			found := findingTypes(t, cfg)
			if found[neuralSentinelType] != neural {
				t.Errorf("Neural Sentinel reported running: %v; reported the scanner: %v", neural, found[neuralSentinelType])
			}
			if found[graphCoordinatedType] != graph {
				t.Errorf("Graph Intelligence reported running: %v; reported the campaign: %v", graph, found[graphCoordinatedType])
			}
		})
	}
}

// findingTypes runs a scanner and a five-address campaign among forty browsers
// through the engine under cfg and returns which finding types it produced.
func findingTypes(t *testing.T, cfg *gateonv1.AnomalyDetectionConfig) map[string]bool {
	t.Helper()
	now := time.Now()
	tf := newTraffic(51, now.Add(-10*time.Minute))
	tf.browsers("10.50", 40)
	tf.scanner("10.57.0.1", 200, 10)
	for v := range 5 {
		tf.classAttacker(fmt.Sprintf("10.58.0.%d", v+1), "t13d0000h1_666666666666_status", 3, now.Add(-time.Minute))
	}
	data := tf.data()
	data.Now = now
	found := map[string]bool{}
	for _, a := range NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{AnomalyDetection: cfg}, nil).Analyze(t.Context(), data) {
		found[a.GetType()] = true
	}
	return found
}
