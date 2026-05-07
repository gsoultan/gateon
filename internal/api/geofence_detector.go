package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// GeofenceDetector detects requests from unauthorized countries.
type GeofenceDetector struct {
	BlockedCountries []string
}

func (d *GeofenceDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly
	if len(d.BlockedCountries) == 0 {
		return nil
	}

	blockedMap := make(map[string]bool)
	for _, c := range d.BlockedCountries {
		blockedMap[c] = true
	}

	for _, tr := range data.Traces {
		country, _, _, _ := telemetry.ResolveIPInfo(tr.SourceIP)
		if country != "" && blockedMap[country] {
			mitigated := false
			// Check if country is already blocked in middlewares (geoip)
			for _, mw := range data.Middlewares {
				if mw.Type == "geoip" && mw.Config != nil {
					if denyList, ok := mw.Config["deny_countries"]; ok {
						for _, c := range strings.Split(denyList, ",") {
							if strings.TrimSpace(c) == country {
								mitigated = true
								break
							}
						}
					}
					if !mitigated {
						if allowList, ok := mw.Config["allow_countries"]; ok && allowList != "" {
							allowed := false
							for _, c := range strings.Split(allowList, ",") {
								if strings.TrimSpace(c) == country {
									allowed = true
									break
								}
							}
							if !allowed {
								mitigated = true
							}
						}
					}
				}
				if mitigated {
					break
				}
			}

			anomaly := &gateonv1.Anomaly{
				Type:           "geofence_violation",
				Severity:       "high",
				Description:    fmt.Sprintf("Request from blocked country: %s", country),
				Timestamp:      tr.Timestamp.Format(time.RFC3339),
				Source:         country, // Use country code as source for geofence
				Recommendation: fmt.Sprintf("Add %s to eBPF/XDP country block list for hardware-level mitigation.", country),
				Mitigated:      mitigated,
			}
			populateAnomalyGeo(anomaly, tr.SourceIP)
			anomalies = append(anomalies, anomaly)
		}
	}
	return anomalies
}
