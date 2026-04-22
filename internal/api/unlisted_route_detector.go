package api

import (
	"context"
	"fmt"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// UnlistedRouteDetector detects requests to routes not present in the configuration.
type UnlistedRouteDetector struct{}

func (d *UnlistedRouteDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly

	for _, tr := range data.Traces {
		if tr.ServiceName == "" || tr.ServiceName == "unknown" {
			anomaly := &gateonv1.Anomaly{
				Type:           "unlisted_route",
				Severity:       "medium",
				Description:    fmt.Sprintf("Request to unlisted route/host: %s", tr.Path),
				Timestamp:      tr.Timestamp.Format(time.RFC3339),
				Source:         tr.SourceIP,
				Recommendation: "Verify if this path should be registered in the proxy configuration or blocked.",
			}
			populateAnomalyGeo(anomaly, tr.CountryCode)
			anomalies = append(anomalies, anomaly)
		}
	}
	return anomalies
}
