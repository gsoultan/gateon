// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// HybridGraphAnomalyDetector identifies coordinated attacks by mapping relationships between
// IPs, Fingerprints, and Paths into a sharded graph and finding dense communities.
type HybridGraphAnomalyDetector struct {
	Config *gateonv1.AnomalyDetectionConfig
}

func (d *HybridGraphAnomalyDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	if d.Config != nil && !d.Config.Enabled {
		return nil
	}

	// 1. Update Global Sharded Graph
	for ip, stats := range data.IPStats {
		if stats.LastTrace != nil && stats.LastTrace.Fingerprint != "" {
			telemetry.AddGraphEdge(ip, "fp:"+stats.LastTrace.Fingerprint, 2.0)
			telemetry.AddGraphEdge("fp:"+stats.LastTrace.Fingerprint, ip, 2.0)

			// Significant edges are broadcasted in distributed mode
			if d.Config != nil && d.Config.Enabled { // Simplified check for distributed
				telemetry.BroadcastGraphEdge(ip, "fp:"+stats.LastTrace.Fingerprint, 2.0, "fp_ip")
			}
		}
		for path := range stats.UniquePaths {
			telemetry.AddGraphEdge(ip, "path:"+path, 1.0)
			telemetry.AddGraphEdge("path:"+path, ip, 1.0)
		}
	}

	// 2. Identify dense subgraphs (Clusters)
	var anomalies []*gateonv1.Anomaly
	graph := telemetry.GetGraphSnapshot()

	for nodeID, neighbors := range graph {
		// Only look at FP hubs
		if !strings.HasPrefix(nodeID, "fp:") {
			continue
		}

		// If a fingerprint connects many IPs, check their behavioral overlap
		if len(neighbors) >= 5 {
			ips := make([]string, 0, len(neighbors))
			for neighborID := range neighbors {
				if !strings.HasPrefix(neighborID, "fp:") && !strings.HasPrefix(neighborID, "path:") {
					ips = append(ips, neighborID)
				}
			}

			if len(ips) >= 5 {
				anomaly := &gateonv1.Anomaly{
					Type:           "graph_coordinated_fp",
					Severity:       "high",
					Description:    fmt.Sprintf("Graph Intelligence detected cluster around fingerprint %s: %d distinct IPs sharing behavior across cluster.", nodeID[3:], len(ips)),
					Source:         strings.Join(ips, ", "),
					Score:          85.0,
					ClusterSize:    int32(len(ips)),
					Timestamp:      time.Now().Format(time.RFC3339),
					Recommendation: "Cluster of IPs sharing the same JA4 fingerprint detected. High likelihood of automated botnet activity.",
				}
				if len(ips) > 0 {
					populateAnomalyGeo(ctx, anomaly, ips[0])
				}
				anomalies = append(anomalies, anomaly)
			}
		}
	}

	return anomalies
}
