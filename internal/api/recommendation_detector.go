// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// RecommendationDetector surfaces smart recommendations captured in traces as anomalies.
type RecommendationDetector struct{}

func (d *RecommendationDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly
	seen := make(map[string]bool)

	for _, tr := range data.Traces {
		if tr.Recommendation != "" {
			// Deduplicate by Source + Recommendation + Route to avoid noise
			key := tr.SourceIP + tr.Recommendation + tr.RouteID
			if seen[key] {
				continue
			}
			seen[key] = true

			severity := "medium"
			anomalyType := "configuration_recommendation"

			if tr.Status == "403" || tr.Status == "401" {
				severity = "high"
				anomalyType = "security_block_recommendation"
			}

			anomalies = append(anomalies, &gateonv1.Anomaly{
				Type:           anomalyType,
				Severity:       severity,
				Description:    tr.Method + " " + tr.Path + " (" + tr.Status + ") triggered a smart recommendation",
				Timestamp:      tr.Timestamp.Format(time.RFC3339),
				Source:         tr.SourceIP,
				Recommendation: tr.Recommendation,
				RouteId:        tr.RouteID,
				RequestUri:     tr.RequestURI,
				UserAgent:      tr.UserAgent,
				HttpMethod:     tr.Method,
				RequestHeaders: tr.RequestHeaders,
				TriggeredRules: tr.Recommendation,
				Id:             tr.ID,
			})
		}
	}

	return anomalies
}
