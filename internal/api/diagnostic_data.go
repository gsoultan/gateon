package api

import (
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// DiagnosticData holds the data needed for anomaly detection.
type DiagnosticData struct {
	Traces           []telemetry.TraceRecord
	Routes           []*gateonv1.Route
	ManagementHosts  []string
	IPStats          map[string]*IPStats
	FingerprintStats map[string]*FingerprintStats
}

type FingerprintStats struct {
	Fingerprint   string
	IPs           map[string]struct{}
	TotalRequests int
	Error4xx      int
	Error5xx      int
	UniquePaths   map[string]struct{}
	LastSeen      time.Time
}
