package api

import (
	"context"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// AnomalyDetector defines the interface for different anomaly detection strategies.
type AnomalyDetector interface {
	Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly
}

func populateAnomalyGeo(a *gateonv1.Anomaly, ip string) {
	if ip == "" {
		return
	}
	country, _, lat, lon := telemetry.ResolveIPInfo(ip)
	if country == "" || country == "XX" {
		// Fallback to coordinates only if we have them but country is unknown
		if lat == 0 && lon == 0 {
			return
		}
	}
	a.CountryCode = country
	a.Latitude = lat
	a.Longitude = lon
}
