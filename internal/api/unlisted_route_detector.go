// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// UnlistedRouteDetector detects requests to routes not present in the configuration.
type UnlistedRouteDetector struct {
	HoneypotPaths []string
}

func (d *UnlistedRouteDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly

	honeypots := make(map[string]bool)
	if len(d.HoneypotPaths) == 0 {
		// Default honeypots
		d.HoneypotPaths = []string{"/.env", "/wp-login.php", "/.git/config", "/admin/config.php"}
	}
	for _, p := range d.HoneypotPaths {
		honeypots[p] = true
	}

	for _, tr := range data.Traces {
		// Skip internal Gateon paths and health checks
		if middleware.IsInternalPath(tr.Path) {
			continue
		}

		// A route is considered "unlisted" if:
		// 1. ServiceName is empty or "unknown"
		// 2. ServiceName starts with "gateon-" (default entrypoint name) - meaning no user route matched.
		// 3. ServiceName is a known default entrypoint ID (http, https, grpc)
		isUnlisted := tr.ServiceName == "" || tr.ServiceName == "unknown" ||
			strings.HasPrefix(tr.ServiceName, "gateon-") ||
			tr.ServiceName == "http" || tr.ServiceName == "https" || tr.ServiceName == "grpc"

		if isUnlisted {
			anomalyType := "unlisted_route"
			severity := "medium"
			description := fmt.Sprintf("Request to unlisted route/host: %s", tr.Path)
			recommendation := "Verify if this path should be registered in the proxy configuration or blocked."

			score := 0.5
			if honeypots[tr.Path] {
				anomalyType = "honeypot_triggered"
				severity = "critical"
				description = fmt.Sprintf("Honeypot triggered! Access to trap route: %s", tr.Path)
				recommendation = "This IP is likely a scanner. Block it immediately at the XDP level."
				score = 0.9
			}

			anomaly := &gateonv1.Anomaly{
				Type:           anomalyType,
				Severity:       severity,
				Description:    description,
				Timestamp:      tr.Timestamp.Format(time.RFC3339),
				Source:         tr.SourceIP,
				RequestUri:     tr.Path,
				Recommendation: recommendation,
				Mitigated:      data.IsIPMitigated(tr.SourceIP),
				Score:          score,
			}
			populateAnomalyGeo(ctx, anomaly, tr.SourceIP)
			anomalies = append(anomalies, anomaly)
		}
	}
	return anomalies
}
