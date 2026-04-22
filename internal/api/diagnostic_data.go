package api

import (
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// DiagnosticData holds the data needed for anomaly detection.
type DiagnosticData struct {
	Traces          []telemetry.TraceRecord
	Routes          []*gateonv1.Route
	ManagementHosts []string
	IPStats         map[string]*IPStats
}
