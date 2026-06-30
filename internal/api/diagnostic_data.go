package api

import (
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// DiagnosticData holds the data needed for anomaly detection.
type DiagnosticData struct {
	Traces           []*telemetry.TraceRecord
	Routes           []*gateonv1.Route
	Middlewares      []*gateonv1.Middleware
	ManagementHosts  []string
	IPStats          map[string]*IPStats
	FingerprintStats map[string]*FingerprintStats
	PathMap          map[uint64]string            // Hash -> Original path
	SequenceStats    map[[3]uint64]*SequenceStats // [3]PathHash -> Aggregated signals
}

type SequenceStats struct {
	IPs        map[string]struct{}
	UserAgents map[string]int
	JA3s       map[string]int
	JA4s       map[string]int
	Countries  map[string]struct{}
	UACount    int
	JA3Count   int
	JA4Count   int
}

// IsIPMitigated checks if an IP is currently blocked or shunned by any middleware.
func (d *DiagnosticData) IsIPMitigated(ip string) bool {
	for _, mw := range d.Middlewares {
		if mw.Type == "ipfilter" {
			if denyList, ok := mw.Config["deny_list"]; ok {
				for _, blockedIP := range strings.Split(denyList, ",") {
					if strings.TrimSpace(blockedIP) == ip {
						return true
					}
				}
			}
		}
	}
	return false
}

// IsCountryMitigated checks if a country is currently blocked by any geoip middleware.
func (d *DiagnosticData) IsCountryMitigated(country string) bool {
	for _, mw := range d.Middlewares {
		if mw.Type == "geoip" && mw.Config != nil {
			if denyList, ok := mw.Config["deny_countries"]; ok {
				for _, c := range strings.Split(denyList, ",") {
					if strings.TrimSpace(c) == country {
						return true
					}
				}
			}
			if allowList, ok := mw.Config["allow_countries"]; ok && allowList != "" {
				allowed := false
				for _, c := range strings.Split(allowList, ",") {
					if strings.TrimSpace(c) == country {
						allowed = true
						break
					}
				}
				if !allowed {
					return true
				}
			}
		}
	}
	return false
}

type FingerprintStats struct {
	Fingerprint   string
	IPs           map[string]struct{}
	TotalRequests int
	Error4xx      int
	Error5xx      int
	UniquePaths   map[string]struct{}
	LastSeen      time.Time
	Countries     map[string]time.Time // CountryCode -> LastSeen
	LastTrace     *telemetry.TraceRecord
}
