package api

import (
	"context"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// AnomalyAnalysisEngine orchestrates different detectors.
type AnomalyAnalysisEngine struct {
	detectors []AnomalyDetector
}

func NewAnomalyAnalysisEngine(config *gateonv1.GlobalConfig, reputation *reputation.IPReputationStore) *AnomalyAnalysisEngine {
	securityThreshold := 30.0
	var behavioral *gateonv1.BehavioralConfig
	if config != nil {
		if config.AnomalyDetection != nil {
			securityThreshold = config.AnomalyDetection.SecurityThreatThreshold
		}
		if config.SecurityAdvanced != nil {
			behavioral = config.SecurityAdvanced.Behavioral
		}
	}

	var blockedCountries []string
	if config != nil && config.Geoip != nil {
		blockedCountries = config.Geoip.BlockedCountries
	}

	return &AnomalyAnalysisEngine{
		detectors: []AnomalyDetector{
			&SecurityThreatDetector{Threshold: securityThreshold, Reputation: reputation, Config: behavioral},
			&UnlistedRouteDetector{},
			&ManagementDomainDetector{},
			&SlowClientDetector{},
			&ShadowedRouteDetector{},
			&GeofenceDetector{BlockedCountries: blockedCountries},
			&IntegrityDetector{},
		},
	}
}

func (e *AnomalyAnalysisEngine) Analyze(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	// Pre-process traces for performance - single pass
	data.IPStats = make(map[string]*IPStats)
	data.FingerprintStats = make(map[string]*FingerprintStats)
	routeMap := make(map[string]*gateonv1.Route)
	for _, r := range data.Routes {
		routeMap[r.Id] = r
	}

	// For burst detection
	type ipTime struct {
		ip   string
		slot int64
	}
	burstTracker := make(map[ipTime]int)

	for _, tr := range data.Traces {
		if tr == nil || tr.SourceIP == "" {
			continue
		}
		stats, ok := data.IPStats[tr.SourceIP]
		if !ok {
			stats = &IPStats{
				UniquePaths: make(map[string]struct{}),
				UserAgents:  make(map[string]struct{}),
				Methods:     make(map[string]int),
				Referers:    make(map[string]int),
				JA3s:        make(map[string]int),
				JA4s:        make(map[string]int),
				PathErrors:  make(map[string]int),
				CountryCode: tr.CountryCode,
			}
			data.IPStats[tr.SourceIP] = stats
		}
		stats.TotalRequests++
		stats.TotalDuration += tr.DurationMs
		if tr.Timestamp.After(stats.LastSeen) {
			stats.LastSeen = tr.Timestamp
			stats.LastTrace = tr
		}
		stats.UniquePaths[tr.Path] = struct{}{}
		if tr.UserAgent != "" {
			stats.UserAgents[tr.UserAgent] = struct{}{}
		}
		if tr.Method != "" {
			stats.Methods[tr.Method]++
		}
		if tr.Referer != "" {
			stats.Referers[tr.Referer]++
		}
		if tr.JA3 != "" {
			stats.JA3s[tr.JA3]++
		}
		if tr.JA4 != "" {
			stats.JA4s[tr.JA4]++
		}

		// Burst detection: 10-second slots
		slot := tr.Timestamp.Unix() / 10
		it := ipTime{tr.SourceIP, slot}
		burstTracker[it]++
		if burstTracker[it] > stats.BurstCount {
			stats.BurstCount = burstTracker[it]
		}

		// Fingerprint aggregation
		if tr.Fingerprint != "" {
			fStats, ok := data.FingerprintStats[tr.Fingerprint]
			if !ok {
				fStats = &FingerprintStats{
					Fingerprint: tr.Fingerprint,
					IPs:         make(map[string]struct{}),
					UniquePaths: make(map[string]struct{}),
					Countries:   make(map[string]time.Time),
				}
				data.FingerprintStats[tr.Fingerprint] = fStats
			}
			fStats.TotalRequests++
			fStats.IPs[tr.SourceIP] = struct{}{}
			fStats.UniquePaths[tr.Path] = struct{}{}
			if tr.CountryCode != "" {
				if last, ok := fStats.Countries[tr.CountryCode]; !ok || tr.Timestamp.After(last) {
					fStats.Countries[tr.CountryCode] = tr.Timestamp
				}
			}
			if tr.Timestamp.After(fStats.LastSeen) {
				fStats.LastSeen = tr.Timestamp
				fStats.LastTrace = tr
			}
			if strings.HasPrefix(tr.Status, "4") {
				fStats.Error4xx++
			} else if strings.HasPrefix(tr.Status, "5") {
				fStats.Error5xx++
			}
		}
		if strings.Contains(tr.Status, "401") {
			stats.Error401++
			stats.PathErrors[tr.Path]++
		} else if strings.Contains(tr.Status, "403") {
			stats.Error403++
			stats.PathErrors[tr.Path]++
		} else if strings.Contains(tr.Status, "404") {
			stats.Error404++
		} else if strings.HasPrefix(tr.Status, "4") {
			stats.Error4xx++
		} else if strings.HasPrefix(tr.Status, "5") {
			stats.Error5xx++
		}

		// Header Consistency Check
		e.checkHeaderConsistency(tr, routeMap[tr.ServiceName], stats)
	}

	var allAnomalies []*gateonv1.Anomaly
	for _, d := range e.detectors {
		allAnomalies = append(allAnomalies, d.Detect(ctx, data)...)
	}
	return allAnomalies
}

func (e *AnomalyAnalysisEngine) checkHeaderConsistency(tr *telemetry.TraceRecord, route *gateonv1.Route, stats *IPStats) {
	if tr.RequestHeaders == "" {
		return // Cannot check if headers were not recorded
	}

	ua := tr.UserAgent
	isMozilla := false
	// Case-insensitive check for mozilla in UA (usually short)
	for i := 0; i < len(ua)-6; i++ {
		if (ua[i] == 'm' || ua[i] == 'M') &&
			(ua[i+1] == 'o' || ua[i+1] == 'O') &&
			(ua[i+2] == 'z' || ua[i+2] == 'Z') &&
			(ua[i+3] == 'i' || ua[i+3] == 'I') &&
			(ua[i+4] == 'l' || ua[i+4] == 'L') &&
			(ua[i+5] == 'l' || ua[i+5] == 'L') &&
			(ua[i+6] == 'a' || ua[i+6] == 'A') {
			isMozilla = true
			break
		}
	}

	routeType := "http"
	if route != nil {
		routeType = strings.ToLower(route.Type)
	}

	headers := tr.RequestHeaders
	if routeType == "grpc" {
		// gRPC routes should have gRPC content-type
		// Use strings.Contains on raw headers. Since Content-Type is canonicalized and
		// application/grpc is standard, this is reasonably safe and fast.
		if !strings.Contains(headers, "application/grpc") {
			if isMozilla {
				stats.HeaderAnomaly++
				return
			}
			if tr.Method != "OPTIONS" && tr.Method != "GET" {
				stats.HeaderAnomaly++
			}
		}

		if isMozilla && !strings.Contains(headers, "X-Grpc-Web") && !strings.Contains(headers, "grpc-timeout") {
			stats.HeaderAnomaly++
		}
	} else {
		// HTTP specific checks
		if isMozilla {
			// Real browsers send Accept, Accept-Language and Accept-Encoding
			// Search for canonicalized keys
			if !strings.Contains(headers, "Accept-Language:") || !strings.Contains(headers, "Accept-Encoding:") {
				stats.HeaderAnomaly++
			}
			if !strings.Contains(headers, "Accept:") {
				stats.HeaderAnomaly++
			}
		}
	}
}
