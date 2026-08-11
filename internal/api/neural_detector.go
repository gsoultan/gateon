// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/e-XpertSolutions/go-iforest/v2/iforest"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// NeuralAnomalyDetector uses an Isolation Forest (Unsupervised ML) to detect zero-day threats
// by finding "mathematical loneliness" in high-dimensional behavioral data.
type NeuralAnomalyDetector struct {
	Config   *gateonv1.AnomalyDetectionConfig
	LowPower int32 // atomic: 0 = normal, 1 = low power
}

// SetLowPower toggles the low-power mode for the ML engine.
func (d *NeuralAnomalyDetector) SetLowPower(enabled bool) {
	if enabled {
		atomic.StoreInt32(&d.LowPower, 1)
	} else {
		atomic.StoreInt32(&d.LowPower, 0)
	}
}

func (d *NeuralAnomalyDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	if d.Config != nil && !d.Config.Enabled {
		return nil
	}

	// 1. Prepare Features per IP
	var features [][]float64
	var ips []string

	for ip, stats := range data.IPStats {
		if stats.TotalRequests < 5 { // Need some baseline for the IP
			continue
		}

		f := d.extractFeatures(stats)
		features = append(features, f)
		ips = append(ips, ip)
	}

	// Isolation Forest needs a reasonable population to identify outliers.
	if len(features) < 20 {
		return nil
	}

	// 2. Train Isolation Forest
	// We use 100 trees, a sample size of 256, and an initial anomaly ratio of 0.05.
	numTrees := 100
	sampleSize := 256
	if atomic.LoadInt32(&d.LowPower) == 1 {
		numTrees = 25
		sampleSize = 64
	}
	forest := iforest.NewForest(numTrees, sampleSize, 0.05)
	forest.Train(features)

	// 3. Score each point
	var anomalies []*gateonv1.Anomaly
	sensitivity := 0.7 // Default sensitivity
	if d.Config != nil && d.Config.Sensitivity > 0 {
		// Map sensitivity (0-100) to anomaly threshold (0.9 - 0.5)
		// Higher sensitivity -> Lower threshold (more anomalies)
		sensitivity = 0.9 - (d.Config.Sensitivity / 100.0 * 0.4)
	}

	_, scores, err := forest.Predict(features)
	if err != nil {
		return nil
	}

	for i, score := range scores {
		if score > sensitivity {
			ip := ips[i]

			anomaly := &gateonv1.Anomaly{
				Type:        "neural_sentinel",
				Severity:    "high",
				Description: fmt.Sprintf("Neural Sentinel detected anomalous behavior (IForest score: %.2f)", score),
				Source:      ip,
				Score:       score * 100,
				Timestamp:   time.Now().Format(time.RFC3339),
			}
			populateAnomalyGeo(ctx, anomaly, ip)

			// Add details about why it's anomalous (what features are outliers)
			// For now, just generic description.
			// In the future, we can do feature importance analysis.

			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

func (d *NeuralAnomalyDetector) extractFeatures(stats *IPStats) []float64 {
	total := float64(stats.TotalRequests)

	// Feature 1: Average Request Duration
	avgDuration := stats.TotalDuration / total

	// Feature 2: Average Inter-Arrival Time (IAT)
	avgIAT := 0.0
	iatStdDev := 0.0
	if stats.IATCount > 0 {
		avgIAT = stats.IATSum / float64(stats.IATCount)
		// StdDev calculation: sqrt(E[X^2] - (E[X])^2)
		variance := (stats.IATSumSq / float64(stats.IATCount)) - (avgIAT * avgIAT)
		if variance > 0 {
			iatStdDev = math.Sqrt(variance)
		}
	}

	// Feature 3: Error Rate
	errorRate := float64(stats.Error4xx+stats.Error5xx) / total

	// Feature 4: Unique Path Ratio (Scanners visit many paths)
	uniquePathRatio := float64(len(stats.UniquePaths)) / total

	// Feature 5: WAF Hit Rate
	wafHitRate := float64(stats.WAFHits) / total

	// Feature 6: Entropy of last request (Complexity of headers/body)
	entropy := 0.0
	if stats.LastTrace != nil {
		content := stats.LastTrace.RequestHeaders + stats.LastTrace.RequestBody
		entropy = d.calculateShannonEntropy(content)
	}

	return []float64{
		avgDuration,
		avgIAT,
		iatStdDev,
		errorRate,
		uniquePathRatio,
		wafHitRate,
		entropy,
	}
}

func (d *NeuralAnomalyDetector) calculateShannonEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[byte]int)
	for i := 0; i < len(data); i++ {
		counts[data[i]]++
	}
	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(len(data))
		entropy -= p * math.Log2(p)
	}
	return entropy
}
