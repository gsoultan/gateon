package api

import (
	"context"
	"hash/maphash"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// AnomalyAnalysisEngine orchestrates different detectors.
type AnomalyAnalysisEngine struct {
	detectors []AnomalyDetector
}

var hashPool = sync.Pool{
	New: func() any {
		return new(maphash.Hash)
	},
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
	data.PathMap = make(map[uint64]string)
	data.SequenceStats = make(map[[3]uint64]*SequenceStats)

	routeMap := make(map[string]*gateonv1.Route)
	for _, r := range data.Routes {
		routeMap[r.Id] = r
	}

	// For burst detection and hashing
	type ipTime struct {
		ip   string
		slot int64
	}
	burstTracker := make(map[ipTime]int)
	hasher := hashPool.Get().(*maphash.Hash)
	defer hashPool.Put(hasher)

	for _, tr := range data.Traces {
		if tr == nil || tr.SourceIP == "" {
			continue
		}

		// 1. Path Hashing & Mapping
		hasher.Reset()
		hasher.WriteString(tr.Path)
		h := hasher.Sum64()
		if _, ok := data.PathMap[h]; !ok {
			data.PathMap[h] = tr.Path
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

		// 2. Behavioral Signals: IAT (Inter-Arrival Time)
		if !stats.LastRequestAt.IsZero() {
			iat := tr.Timestamp.Sub(stats.LastRequestAt).Seconds() * 1000 // ms
			if iat > 0 {
				stats.IATSum += iat
				stats.IATSumSq += iat * iat
				stats.IATCount++
			}
		}
		stats.LastRequestAt = tr.Timestamp

		// 3. Coordination Signals: Sequence Aggregation
		// Skip consecutive duplicate paths (polling)
		if h != stats.LastPathHash {
			if stats.PrevPathHash != 0 && stats.LastPathHash != 0 {
				sig := [3]uint64{stats.PrevPathHash, stats.LastPathHash, h}
				sStats, ok := data.SequenceStats[sig]
				if !ok {
					sStats = &SequenceStats{
						IPs:        make(map[string]struct{}),
						UserAgents: make(map[string]int),
						JA3s:       make(map[string]int),
						JA4s:       make(map[string]int),
						Countries:  make(map[string]struct{}),
					}
					data.SequenceStats[sig] = sStats
				}
				if _, seen := sStats.IPs[tr.SourceIP]; !seen {
					sStats.IPs[tr.SourceIP] = struct{}{}
					if tr.UserAgent != "" {
						sStats.UserAgents[tr.UserAgent]++
						sStats.UACount++
					}
					if tr.JA3 != "" {
						sStats.JA3s[tr.JA3]++
						sStats.JA3Count++
					}
					if tr.JA4 != "" {
						sStats.JA4s[tr.JA4]++
						sStats.JA4Count++
					}
					if tr.CountryCode != "" {
						sStats.Countries[tr.CountryCode] = struct{}{}
					}
				}
			}
			stats.PrevPathHash = stats.LastPathHash
			stats.LastPathHash = h
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
		return
	}

	uaLower := strings.ToLower(tr.UserAgent)
	isMozilla := strings.Contains(uaLower, "mozilla")

	routeType := "http"
	if route != nil {
		routeType = strings.ToLower(route.Type)
	}

	headers := tr.RequestHeaders
	if routeType == "grpc" {
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
		if isMozilla {
			if !strings.Contains(headers, "Accept-Language:") || !strings.Contains(headers, "Accept-Encoding:") {
				stats.HeaderAnomaly++
			}
			if !strings.Contains(headers, "Accept:") {
				stats.HeaderAnomaly++
			}
		}
	}
}
