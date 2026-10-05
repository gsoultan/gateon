// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/maphash"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/security/waf"
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
	var anomalyConfig *gateonv1.AnomalyDetectionConfig
	if config != nil {
		if config.Geoip != nil {
			blockedCountries = config.Geoip.BlockedCountries
		}
		anomalyConfig = config.AnomalyDetection
	}

	return &AnomalyAnalysisEngine{
		detectors: []AnomalyDetector{
			&SecurityThreatDetector{Threshold: securityThreshold, Reputation: reputation, Config: behavioral},
			&NeuralAnomalyDetector{Config: anomalyConfig},
			&HybridGraphAnomalyDetector{Config: anomalyConfig},
			&UnlistedRouteDetector{},
			&ManagementDomainDetector{},
			&SlowClientDetector{},
			&ShadowedRouteDetector{},
			&GeofenceDetector{BlockedCountries: blockedCountries},
			&IntegrityDetector{},
			&RecommendationDetector{},
		},
	}
}

// SetLowPower toggles low-power mode for underlying detectors.
func (e *AnomalyAnalysisEngine) SetLowPower(enabled bool) {
	for _, d := range e.detectors {
		if nd, ok := d.(*NeuralAnomalyDetector); ok {
			nd.SetLowPower(enabled)
		}
	}
}

var commonCRSRules = map[string]string{
	"920300":  "Request Missing an Accept Header",
	"920320":  "Missing User-Agent Header",
	"920350":  "Host Header is a IP Address",
	"920420":  "Protocol: Content-Type Not Allowed",
	"920180":  "Protocol: POST Missing Content-Length",
	"930100":  "Local File Inclusion",
	"930110":  "Local File Inclusion (Traversals)",
	"932100":  "Remote Command Execution (RCE)",
	"932110":  "RCE: Shell Command Injection",
	"933100":  "PHP Injection Attack",
	"934100":  "Generic Application Attack",
	"941100":  "XSS: Script Tag Injection",
	"942100":  "SQL Injection Attack",
	"949110":  "Inbound Anomaly Score Exceeded",
	"1900001": "Fast-Path: Signature Match",
	"1900002": "Fast-Path: High Entropy Payload",
	"1900003": "Fast-Path: Fingerprint Mismatch",
	"1900004": "Fast-Path: Protocol Violation",
	"1900005": "Fast-Path: Suspicious Client",
	"1990002": "Fast-Path: Malformed Security Token",
	"210001":  "Online Gambling Site Detection",
	"210002":  "Malicious JavaScript Detection",
	"210003":  "PHP Vulnerability Exploit Attempt",
	"210004":  "Arbitrary File Upload Execution Attempt",
}

func getRuleDescription(id string) string {
	if name, ok := commonCRSRules[id]; ok {
		return name
	}
	if store := waf.GetStore(); store != nil {
		if r, ok := store.GetRule(id); ok {
			return r.Name
		}
	}
	return fmt.Sprintf("Rule %s", id)
}

// Analyze aggregates the pass's traces and threats per address and runs every
// detector over the result.
func (e *AnomalyAnalysisEngine) Analyze(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	data.Traces = tracesForAnalysis(data.Traces)
	data.SecurityThreats = threatsForAnalysis(data.SecurityThreats)
	e.aggregate(data)
	return capAnomalies(e.runDetectors(ctx, data))
}

// tracesForAnalysis drops loopback traffic -- management and test calls would
// otherwise skew every statistic -- and puts the rest oldest first.
//
// Oldest first, because the trace store hands back its newest trace first, and
// every order-dependent signal below was computed backwards: the gap between a
// client's requests came out negative for every pair and was thrown away, so no
// client ever had an interval measured, and the three-path sequences read each
// visit in reverse.
func tracesForAnalysis(in []*telemetry.TraceRecord) []*telemetry.TraceRecord {
	out := make([]*telemetry.TraceRecord, 0, len(in))
	for _, tr := range in {
		if tr != nil && !httputil.IsLoopback(tr.SourceIP) {
			out = append(out, tr)
		}
	}
	slices.SortStableFunc(out, func(a, b *telemetry.TraceRecord) int {
		return a.Timestamp.Compare(b.Timestamp)
	})
	return out
}

// threatsForAnalysis drops loopback threats, as tracesForAnalysis drops
// loopback traces.
func threatsForAnalysis(in []*telemetry.SecurityThreat) []*telemetry.SecurityThreat {
	out := make([]*telemetry.SecurityThreat, 0, len(in))
	for _, th := range in {
		if th != nil && !httputil.IsLoopback(th.SourceIP) {
			out = append(out, th)
		}
	}
	return out
}

// aggregate builds the per-address, per-fingerprint and per-sequence views the
// detectors read, in one pass over the traces and one over the threats.
func (e *AnomalyAnalysisEngine) aggregate(data *DiagnosticData) {
	data.IPStats = make(map[string]*IPStats)
	data.FingerprintStats = make(map[string]*FingerprintStats)
	data.PathMap = make(map[uint64]string)
	data.SequenceStats = make(map[[3]uint64]*SequenceStats)
	data.PathPopularity = make(map[string]int)
	data.PathIPs = make(map[string]map[string]struct{})

	agg := newTraceAggregator(data)
	defer agg.release()
	for _, tr := range data.Traces {
		agg.add(tr)
	}

	evidenceSince := data.now().Add(-attackEvidenceWindow)
	for _, th := range data.SecurityThreats {
		aggregateThreat(data, th, evidenceSince)
	}
}

// runDetectors runs every detector concurrently over the aggregated data.
func (e *AnomalyAnalysisEngine) runDetectors(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var allAnomalies []*gateonv1.Anomaly
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)

	for _, d := range e.detectors {
		det := d
		g.Go(func() error {
			res := det.Detect(gctx, data)
			if len(res) > 0 {
				mu.Lock()
				allAnomalies = append(allAnomalies, res...)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	return allAnomalies
}

// newIPStats is an empty per-address record.
func newIPStats(countryCode string) *IPStats {
	return &IPStats{
		UniquePaths: make(map[string]struct{}),
		UserAgents:  make(map[string]struct{}),
		Methods:     make(map[string]int),
		Referers:    make(map[string]int),
		JA4s:        make(map[string]int),
		CountryCode: countryCode,
	}
}

// ipSlot is one address in one 10-second slot, for burst detection.
type ipSlot struct {
	ip   string
	slot int64
}

// traceAggregator folds traces, oldest first, into DiagnosticData.
//
// It reads no header. The traces it is handed are summaries (analysisTraces),
// and the one check that wanted headers -- a client calling itself Mozilla
// without Accept-Language -- was removed rather than paid for: see
// TestAnalysisReadsTraceSummariesOnly.
type traceAggregator struct {
	data   *DiagnosticData
	hasher *maphash.Hash
	bursts map[ipSlot]int
}

func newTraceAggregator(data *DiagnosticData) *traceAggregator {
	hasher, _ := hashPool.Get().(*maphash.Hash)
	if hasher == nil {
		hasher = new(maphash.Hash)
	}
	return &traceAggregator{data: data, hasher: hasher, bursts: make(map[ipSlot]int)}
}

// release returns the pooled hasher.
func (a *traceAggregator) release() {
	hashPool.Put(a.hasher)
}

// add folds one trace in.
func (a *traceAggregator) add(tr *telemetry.TraceRecord) {
	if tr == nil || tr.SourceIP == "" {
		return
	}
	h := a.pathHash(tr.Path)
	stats := a.ipStats(tr)
	a.countRequest(stats, tr)
	countInterval(stats, tr)
	a.countSequence(stats, tr, h)
	a.countBurst(stats, tr)
	a.countFingerprint(tr)
	countStatus(stats, tr)
}

// pathHash hashes a path and remembers the path it came from.
func (a *traceAggregator) pathHash(path string) uint64 {
	a.hasher.Reset()
	_, _ = a.hasher.WriteString(path)
	h := a.hasher.Sum64()
	if _, ok := a.data.PathMap[h]; !ok {
		a.data.PathMap[h] = path
	}
	return h
}

// ipStats is the trace's address record, created on first sight.
func (a *traceAggregator) ipStats(tr *telemetry.TraceRecord) *IPStats {
	stats, ok := a.data.IPStats[tr.SourceIP]
	if !ok {
		stats = newIPStats(tr.CountryCode)
		a.data.IPStats[tr.SourceIP] = stats
	}
	return stats
}

// countRequest records the request's size-independent facts: volume, timing,
// path and client identifiers.
func (a *traceAggregator) countRequest(stats *IPStats, tr *telemetry.TraceRecord) {
	stats.TotalRequests++
	stats.TotalDuration += tr.DurationMs
	if tr.Timestamp.After(stats.LastSeen) {
		stats.LastSeen = tr.Timestamp
		stats.LastTrace = tr
	}
	stats.UniquePaths[tr.Path] = struct{}{}
	lp := strings.ToLower(tr.Path)
	a.data.PathPopularity[lp]++
	if _, ok := a.data.PathIPs[lp]; !ok {
		a.data.PathIPs[lp] = make(map[string]struct{})
	}
	a.data.PathIPs[lp][tr.SourceIP] = struct{}{}

	if tr.UserAgent != "" {
		stats.UserAgents[tr.UserAgent] = struct{}{}
	}
	if tr.Method != "" {
		stats.Methods[tr.Method]++
	}
	if tr.Referer != "" {
		stats.Referers[tr.Referer]++
	}
	if tr.JA4 != "" {
		stats.JA4s[tr.JA4]++
	}
}

// countInterval records the gap since the address's previous request.
//
// A zero gap counts: two requests in the same instant are what a browser
// fetching a page's assets in parallel looks like, and leaving them out made
// that burst read as a steady, machine-like rhythm.
func countInterval(stats *IPStats, tr *telemetry.TraceRecord) {
	if !stats.LastRequestAt.IsZero() {
		if iat := tr.Timestamp.Sub(stats.LastRequestAt).Seconds() * 1000; iat >= 0 { // ms
			stats.IATSum += iat
			stats.IATSumSq += iat * iat
			stats.IATCount++
		}
	}
	stats.LastRequestAt = tr.Timestamp
}

// countSequence aggregates the three-path sequences coordinated-scan detection
// compares across addresses. Consecutive repeats of one path (polling) are
// skipped.
func (a *traceAggregator) countSequence(stats *IPStats, tr *telemetry.TraceRecord, h uint64) {
	if h == stats.LastPathHash {
		return
	}
	if stats.PrevPathHash != 0 && stats.LastPathHash != 0 {
		a.sequence([3]uint64{stats.PrevPathHash, stats.LastPathHash, h}).add(tr)
	}
	stats.PrevPathHash = stats.LastPathHash
	stats.LastPathHash = h
}

// sequence is the record for one three-path sequence, created on first sight.
func (a *traceAggregator) sequence(sig [3]uint64) *SequenceStats {
	sStats, ok := a.data.SequenceStats[sig]
	if !ok {
		sStats = &SequenceStats{
			IPs:        make(map[string]struct{}),
			UserAgents: make(map[string]int),
			JA4s:       make(map[string]int),
			Countries:  make(map[string]struct{}),
		}
		a.data.SequenceStats[sig] = sStats
	}
	return sStats
}

// add counts the trace's client under the sequence, once per address.
func (s *SequenceStats) add(tr *telemetry.TraceRecord) {
	if _, seen := s.IPs[tr.SourceIP]; seen {
		return
	}
	s.IPs[tr.SourceIP] = struct{}{}
	if tr.UserAgent != "" {
		s.UserAgents[tr.UserAgent]++
		s.UACount++
	}
	if tr.JA4 != "" {
		s.JA4s[tr.JA4]++
		s.JA4Count++
	}
	if tr.CountryCode != "" {
		s.Countries[tr.CountryCode] = struct{}{}
	}
}

// countBurst tracks the address's busiest 10-second slot.
func (a *traceAggregator) countBurst(stats *IPStats, tr *telemetry.TraceRecord) {
	it := ipSlot{tr.SourceIP, tr.Timestamp.Unix() / 10}
	a.bursts[it]++
	if a.bursts[it] > stats.BurstCount {
		stats.BurstCount = a.bursts[it]
	}
}

// countFingerprint aggregates the trace under its behavioural fingerprint.
func (a *traceAggregator) countFingerprint(tr *telemetry.TraceRecord) {
	if tr.Fingerprint == "" {
		return
	}
	fStats, ok := a.data.FingerprintStats[tr.Fingerprint]
	if !ok {
		fStats = &FingerprintStats{
			Fingerprint: tr.Fingerprint,
			IPs:         make(map[string]struct{}),
			UniquePaths: make(map[string]struct{}),
			Countries:   make(map[string]time.Time),
		}
		a.data.FingerprintStats[tr.Fingerprint] = fStats
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

// countStatus files the response under the counters the detectors read.
func countStatus(stats *IPStats, tr *telemetry.TraceRecord) {
	post := tr.Method == http.MethodPost
	if post {
		stats.Posts++
	}
	switch {
	case strings.Contains(tr.Status, "401"), strings.Contains(tr.Status, "403"):
		if strings.Contains(tr.Status, "401") {
			stats.Error401++
		} else {
			stats.Error403++
		}
		if credentialAttempt(tr) {
			countCredentialFailure(stats, tr.Path)
		}
		if post {
			stats.PostAuthFailures++
		}
	case strings.Contains(tr.Status, "404"):
		stats.Error404++
	case strings.HasPrefix(tr.Status, "4"):
		stats.Error4xx++
	case strings.HasPrefix(tr.Status, "5"):
		stats.Error5xx++
	default:
		return
	}
	if stats.FailedPaths == nil {
		stats.FailedPaths = make(map[string]int)
	}
	stats.FailedPaths[tr.Path]++
}

// countCredentialFailure records a refused credential attempt on path.
func countCredentialFailure(stats *IPStats, path string) {
	stats.CredentialFailures++
	if stats.CredentialFailurePaths == nil {
		stats.CredentialFailurePaths = make(map[string]int)
	}
	stats.CredentialFailurePaths[path]++
}

// aggregateThreat folds one recorded threat into its address's record.
//
// Only an attack decision held against its source counts (attackEvidenceWeight,
// ADR 0055, 0059): a request the WAF refused on an attack payload, a trap
// sprung, a malware upload, a brute-force or exploit-scan detection. A hit is
// one the request path refused when it recorded it; a warning is one it
// recorded and let through. Every stored threat used to count -- a hit when it
// was mitigated, which on read includes "the address is shunned now", a
// warning otherwise -- so a refusal of an earlier shun, a rate limit or a
// geofence block was a WAF hit worth eight warnings, a detection the gateway
// let through was a warning, and so was this engine's own finding from the
// last pass. The stored row says which are held (migration 69).
func aggregateThreat(data *DiagnosticData, th *telemetry.SecurityThreat, evidenceSince time.Time) {
	if th == nil || th.SourceIP == "" {
		return
	}
	weight := attackEvidenceWeight(th)
	if weight == 0 {
		return
	}
	stats, ok := data.IPStats[th.SourceIP]
	if !ok {
		stats = newIPStats(th.CountryCode)
		data.IPStats[th.SourceIP] = stats
	}
	if th.RefusedWhenRecorded() {
		stats.WAFHits++
	} else {
		stats.WAFWarnings++
	}
	if th.TriggeredRules != "" {
		countTriggeredRules(stats, th.TriggeredRules)
	}
	if th.Time.After(stats.LastSeen) {
		stats.LastSeen = th.Time
	}
	if !th.Time.Before(evidenceSince) {
		stats.AttackEvidence += weight
	}
}

// countTriggeredRules tallies the WAF rules a threat names.
func countTriggeredRules(stats *IPStats, triggered string) {
	if stats.WAFRules == nil {
		stats.WAFRules = make(map[string]int)
	}
	var ruleIDs []int
	if err := json.Unmarshal([]byte(triggered), &ruleIDs); err == nil {
		for _, id := range ruleIDs {
			stats.WAFRules[getRuleDescription(fmt.Sprintf("%d", id))]++
		}
		return
	}
	stats.WAFRules[getRuleDescription(triggered)]++
}

// attackEvidenceWindow is how long a recorded threat counts as evidence against
// its address. Half an hour: long enough to cover the analysis window of a
// quiet site, short enough that an address handed to someone else stops
// carrying a stranger's record the same afternoon.
const attackEvidenceWindow = 30 * time.Minute

// attackEvidenceWeight is what a recorded threat says about its source address.
// The definition is telemetry.AttackEvidenceWeight, which the fingerprint block
// on the recording path uses too: one answer to "is this an attack", wherever
// evidence can end in a limit.
func attackEvidenceWeight(th *telemetry.SecurityThreat) float64 {
	return telemetry.AttackEvidenceWeight(th)
}

// maxAnomaliesPerPass bounds what a single detection pass returns.
//
// The result was previously whatever every detector produced, concatenated. It
// was bounded in practice, but only as a consequence of the caller limiting its
// inputs to 1000 traces and 1000 threats -- nothing here said so, and a detector
// that emitted several anomalies per input would have grown past it unnoticed.
// The ceiling is stated rather than inherited.
//
// 1000 matches those input limits: a pass cannot usefully report more findings
// than it examined records, and the result is held in a single cache slot the
// Diagnostics view reads.
const maxAnomaliesPerPass = 1000

// severityRank orders severities worst-first. Unknown values sort last rather
// than first: a detector inventing a severity should not outrank a known
// critical, and doing so would let a typo push real findings out of a truncated
// pass.
func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case severityCritical:
		return 4
	case severityHigh:
		return 3
	case severityMedium, "warning":
		return 2
	case severityLow, "info":
		return 1
	default:
		return 0
	}
}

// capAnomalies enforces maxAnomaliesPerPass, keeping the most severe.
//
// Truncating the tail of an unordered slice would drop findings at random, so
// the pass is ordered by severity and then score before it is cut. Dropping is
// logged: a cap that silently discards security findings reads, from the
// dashboard, exactly like a quiet period.
func capAnomalies(anomalies []*gateonv1.Anomaly) []*gateonv1.Anomaly {
	if len(anomalies) <= maxAnomaliesPerPass {
		return anomalies
	}

	sort.SliceStable(anomalies, func(i, j int) bool {
		ri, rj := severityRank(anomalies[i].GetSeverity()), severityRank(anomalies[j].GetSeverity())
		if ri != rj {
			return ri > rj
		}
		return anomalies[i].GetScore() > anomalies[j].GetScore()
	})

	dropped := len(anomalies) - maxAnomaliesPerPass
	logger.L.LogWarn("anomaly pass exceeded its cap; keeping the most severe findings",
		"produced", len(anomalies), "cap", maxAnomaliesPerPass, "dropped", dropped)

	return anomalies[:maxAnomaliesPerPass]
}
