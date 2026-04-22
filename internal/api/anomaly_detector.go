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

func populateAnomalyGeo(a *gateonv1.Anomaly, countryCode string) {
	if countryCode == "" || countryCode == "XX" {
		return
	}
	a.CountryCode = countryCode
	lat, lon := telemetry.GetCountryCoordinates(countryCode)
	a.Latitude = lat
	a.Longitude = lon
}
