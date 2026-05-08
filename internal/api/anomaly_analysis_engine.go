package api

import (
	"context"
	"strings"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// AnomalyAnalysisEngine orchestrates different detectors.
type AnomalyAnalysisEngine struct {
	detectors []AnomalyDetector
}

func NewAnomalyAnalysisEngine(config *gateonv1.GlobalConfig, reputation *IPReputationStore) *AnomalyAnalysisEngine {
	securityThreshold := 30.0
	if config != nil && config.AnomalyDetection != nil {
		securityThreshold = config.AnomalyDetection.SecurityThreatThreshold
	}

	var blockedCountries []string
	if config != nil && config.Geoip != nil {
		blockedCountries = config.Geoip.BlockedCountries
	}

	return &AnomalyAnalysisEngine{
		detectors: []AnomalyDetector{
			&SecurityThreatDetector{Threshold: securityThreshold, Reputation: reputation},
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

	// For burst detection
	type ipTime struct {
		ip   string
		slot int64
	}
	burstTracker := make(map[ipTime]int)

	for _, tr := range data.Traces {
		if tr.SourceIP == "" {
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
	}

	var allAnomalies []*gateonv1.Anomaly
	for _, d := range e.detectors {
		allAnomalies = append(allAnomalies, d.Detect(ctx, data)...)
	}
	return allAnomalies
}
