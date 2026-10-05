// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"cmp"
	"context"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/ai"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/sync/errgroup"
)

// internalRoutePrefix marks Gateon's own management routes. They are excluded
// from route metrics so the dashboard reports customer traffic, not the
// gateway talking to itself.
const internalRoutePrefix = "gateon-"

type EbpfProvider interface {
	GetTopIPs(limit int) ([]ebpf.IPStat, error)
	ShunIP(ip string) error
	UnshunIP(ip string) error
	SetAdaptiveRateLimit(ip string, interval time.Duration) error
}

type ebpfProviderContainer struct {
	p EbpfProvider
}

type TitanProvider interface {
	GetStatus() (enabled bool, engine string, activePorts int)
}

type titanProviderContainer struct {
	p TitanProvider
}

type GovernorProvider interface {
	GetStatus(ctx context.Context) (active bool, memHooks, cpuHooks int, memPressure, cpuPressure float64)
}

type governorProviderContainer struct {
	p GovernorProvider
}

// TargetHealthCounts is the live state of the gateway's backend targets, as
// the dashboard's target and circuit tiles count it: an alive target is
// healthy with its circuit closed, any other is down with its circuit open.
type TargetHealthCounts struct {
	Healthy int
	Down    int
	Total   int
}

// TargetHealthProvider reports TargetHealthCounts from the load balancers'
// own state. The snapshot used to count gateon_target_health instead, which
// exists only for health-checked targets and has no "status" label to read, so
// realtime updates showed zero healthy targets whatever the backends did.
type TargetHealthProvider interface {
	TargetHealthCounts() TargetHealthCounts
}

type targetHealthProviderContainer struct {
	p TargetHealthProvider
}

var (
	globalEbpfManager  atomic.Value // stores *ebpfProviderContainer
	globalTitan        atomic.Value // stores *titanProviderContainer
	globalGovernor     atomic.Value // stores *governorProviderContainer
	globalTargetHealth atomic.Value // stores *targetHealthProviderContainer
	globalVersion      atomic.Value // stores string
	lastSnapshot       atomic.Pointer[MetricsSnapshot]
)

// SetTargetHealthProvider registers where the snapshot reads target health.
func SetTargetHealthProvider(p TargetHealthProvider) {
	globalTargetHealth.Store(&targetHealthProviderContainer{p: p})
}

// CurrentTargetHealth is the registered provider's counts, or zero before one
// is registered.
func CurrentTargetHealth() TargetHealthCounts {
	if c, ok := globalTargetHealth.Load().(*targetHealthProviderContainer); ok && c.p != nil {
		return c.p.TargetHealthCounts()
	}
	return TargetHealthCounts{}
}

// RouteBreakerCounts is how many route circuit breakers are open and how many
// half-open, read from gateon_circuit_breaker_state.
func RouteBreakerCounts() (open, halfOpen int) {
	ch := make(chan prometheus.Metric, 64)
	go func() {
		CircuitBreakerState.Collect(ch)
		close(ch)
	}()
	for m := range ch {
		var d dto.Metric
		if m.Write(&d) != nil || d.GetGauge().GetValue() < 1 {
			continue
		}
		switch labelValue(&d, "state") {
		case "open":
			open++
		case "half-open":
			halfOpen++
		}
	}
	return open, halfOpen
}

func SetEbpfManager(m EbpfProvider) {
	globalEbpfManager.Store(&ebpfProviderContainer{p: m})
}

func SetTitanProvider(p TitanProvider) {
	globalTitan.Store(&titanProviderContainer{p: p})
}

func SetGovernorProvider(p GovernorProvider) {
	globalGovernor.Store(&governorProviderContainer{p: p})
}

func SetVersion(v string) {
	globalVersion.Store(v)
}

// DetectorStatusProvider reports whether the analysis loop runs the Neural
// Sentinel and Graph Intelligence under the current configuration.
type DetectorStatusProvider func() (neuralSentinel, graphIntelligence bool)

var globalDetectorStatus atomic.Pointer[DetectorStatusProvider]

// SetDetectorStatusProvider registers where the snapshot reads the detectors'
// status. The API package owns the answer, since it owns the conditions the
// detectors check before they run.
func SetDetectorStatusProvider(p DetectorStatusProvider) {
	globalDetectorStatus.Store(&p)
}

// detectorStatus is the registered provider's answer, or off before one is
// registered. Both flags used to be true unconditionally -- on every install,
// including the default one, where anomaly detection is off and neither
// detector runs.
func detectorStatus() (neuralSentinel, graphIntelligence bool) {
	if p := globalDetectorStatus.Load(); p != nil && *p != nil {
		return (*p)()
	}
	return false, false
}

func GetLastSnapshot() *MetricsSnapshot {
	return lastSnapshot.Load()
}

// StartSnapshotLoop starts a background goroutine to periodically refresh the
// global metrics snapshot, ensuring the UI remains fast even under load.
func StartSnapshotLoop(ctx context.Context) {
	timer := time.NewTimer(100 * time.Millisecond) // Start soon
	defer timer.Stop()

	heavyCounter := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			td := config.CurrentTierDefaults()

			heavyThreshold := 1 // By default, every refresh is heavy for standard/enterprise
			if td.Tier == config.TierMinimal {
				heavyThreshold = 4 // For minimal, 1 heavy every 4 cycles (e.g. 30s * 4 = 2 min)
			}

			heavyCounter++
			isHeavy := heavyCounter >= heavyThreshold
			if isHeavy {
				heavyCounter = 0
			}

			refreshSnapshot(ctx, isHeavy)

			interval := time.Duration(td.TelemetryIntervalSeconds) * time.Second
			if interval <= 0 {
				interval = 5 * time.Second
			}
			timer.Reset(interval)
		}
	}
}

// refreshSnapshot collects a snapshot, publishes it and pushes it to live
// subscribers.
//
// The snapshot it replaces is left to the garbage collector. It used to go back
// into a sync.Pool at this point, while the pointer had already been handed to
// whoever called GetLastSnapshot or CollectMetricsSnapshot and sat in every
// /v1/watch subscriber's channel -- and light refreshes alias the previous
// snapshot's slices into the new one. The next Get()+Reset() then zeroed and
// refilled an object that readers were still encoding: the race detector flags
// the encoder, a slow SSE client serialises someone else's numbers, and on the
// minimal tier the live snapshot's traffic history and security insights were
// zeroed in place. One allocation per telemetry interval is the price of a
// snapshot that is immutable once published.
func refreshSnapshot(ctx context.Context, heavy bool) {
	snap, err := collectMetricsSnapshot(ctx, 50, 0, heavy)
	if err != nil {
		return
	}
	lastSnapshot.Store(snap)
	MetricsBroadcaster.Broadcast(snap)
}

// MetricsSnapshot holds a structured view of all Prometheus metrics for the UI.
type MetricsSnapshot struct {
	// Golden signals
	GoldenSignals GoldenSignals `json:"goldenSignals,omitzero"`

	// Per-route request metrics broken down by status code.
	RouteMetrics []RouteMetric `json:"routeMetrics,omitzero"`

	// Middleware counters (rate limit, WAF, cache, auth, compress, turnstile, geoip, hmac).
	Middleware MiddlewareMetrics `json:"middleware,omitzero"`

	// TLS certificate expiry information.
	TLSCertificates []TLSCertMetric `json:"tlsCertificates,omitzero"`

	// Target health and connection status.
	Targets []TargetMetric `json:"targets,omitzero"`

	// IP-based metrics
	IPMetrics []IPMetric `json:"ipMetrics,omitzero"`

	// Country-based metrics
	CountryMetrics []CountryMetric `json:"countryMetrics,omitzero"`

	// Protocol-based metrics
	ProtocolMetrics []LabeledCount `json:"protocolMetrics,omitzero"`

	// Domain-based metrics
	DomainMetrics []DomainMetric `json:"domainMetrics,omitzero"`

	// Hourly domain metrics (current hour)
	HourlyDomainMetrics []DomainStats `json:"hourlyDomainMetrics,omitzero"`

	// Rolling 24h domain metrics
	DomainStatsRolling24h []DomainStats `json:"domainStatsRolling24h,omitzero"`

	// Traffic history for charts (last 24-48 hours)
	TrafficHistory []TrafficSample `json:"trafficHistory,omitzero"`

	// Active threats
	ActiveSuspiciousSessions  float64        `json:"activeSuspiciousSessions"`
	ActiveUnverifiedClients   float64        `json:"activeUnverifiedClients"`
	ActiveShunnedEntities     []LabeledCount `json:"activeShunnedEntities,omitzero"`
	ActiveAnomalyScoreAverage float64        `json:"activeAnomalyScoreAverage"`

	// System-level gauges.
	System SystemMetrics `json:"system,omitzero"`

	// Security insights
	Security SecurityInsights `json:"security,omitzero"`

	// Reconciled mitigation funnel (single-unit, server-computed).
	MitigationFunnel MitigationFunnel `json:"mitigationFunnel,omitzero"`
}

// MitigationFunnel is what became of the HTTP requests the gateway received,
// each counted once (ADR 0048).
//
//	HTTPIngress == Allowed + Refused + Answered
//
// holds by construction: all three come from gateon_request_outcomes_total,
// which the request's Metrics middleware increments once per request. Allowed
// is what reached a backend; Refused what the gateway answered with an error
// before any backend saw it; Answered what it answered itself without one
// (redirects, challenge pages, cached responses).
//
// The per-stage counts say which control refused, from the counters each
// control (or the threat pipeline, for the ones that record a threat) keeps.
// OtherRefused is the refusals no stage claims -- IP and host filters,
// request limits, no matching route -- so the stages and it add up to
// Refused. A stage counter that ran ahead of the outcome count (a restart
// in between) leaves OtherRefused at zero rather than negative.
//
// The old funnel summed gateon_requests_total across every label, and a
// proxied request is recorded under its entrypoint's and its route's: every
// request counted twice, and the refusals no counter covered (IP filters)
// were shown as "Allowed".
//
// TotalMitigated is Refused, kept for API compatibility. ServerErrors (5xx
// among the requests, counted once) and XDPPacketsDropped (packets, a
// different unit) are reported beside the funnel, not as stages.
type MitigationFunnel struct {
	HTTPIngress           float64 `json:"httpIngress"`
	WAFBlocked            float64 `json:"wafBlocked"`
	FastPathBlocked       float64 `json:"fastPathBlocked"`
	RateLimited           float64 `json:"rateLimited"`
	GeoIPBlocked          float64 `json:"geoipBlocked"`
	AuthFailures          float64 `json:"authFailures"`
	TurnstileFailures     float64 `json:"turnstileFailures"`
	HMACFailures          float64 `json:"hmacFailures"`
	BotBlocked            float64 `json:"botBlocked"`
	FileSecurityBlocked   float64 `json:"fileSecurityBlocked"`
	DeceptionBlocked      float64 `json:"deceptionBlocked"`
	MitigationBlocked     float64 `json:"mitigationBlocked"`
	AdvancedSecurityBlock float64 `json:"advancedSecurityBlocked"`
	OtherRefused          float64 `json:"otherRefused"`
	Refused               float64 `json:"refused"`
	Answered              float64 `json:"answered"`
	TotalMitigated        float64 `json:"totalMitigated"`
	Allowed               float64 `json:"allowed"`
	ServerErrors          float64 `json:"serverErrors"`
	XDPPacketsDropped     float64 `json:"xdpPacketsDropped"`
}

type SecurityInsights struct {
	TopThreatSources  []LabeledCount    `json:"topThreatSources,omitzero"`
	TopThreatTypes    []LabeledCount    `json:"topThreatTypes,omitzero"`
	ThreatsByCountry  []LabeledCount    `json:"threatsByCountry,omitzero"`
	AttackTrend       []TrafficSample   `json:"attackTrend,omitzero"`
	RecentAnomalies   []*SecurityThreat `json:"recentAnomalies,omitzero"`
	TotalAnomalies    int64             `json:"totalAnomalies"`
	ActiveThreats     int               `json:"activeThreats"`
	MitigatedToday    int               `json:"mitigatedToday"`
	HeavyHitters      []HeavyHitter     `json:"heavyHitters,omitzero"`
	GlobalThreatScore float64           `json:"globalThreatScore"`
	EbpfTopIPs        []IPStat          `json:"ebpfTopIPs,omitzero"`
}

type IPStat struct {
	IP    string `json:"ip"`
	Count uint64 `json:"count"`
}

// GoldenSignals represents the four golden signals of monitoring.
type GoldenSignals struct {
	RequestsTotal    float64 `json:"requestsTotal"`
	ErrorsTotal      float64 `json:"errorsTotal"`
	ErrorRate        float64 `json:"errorRate"`
	AvgLatencyMs     float64 `json:"avgLatencyMs"`
	P50LatencyMs     float64 `json:"p50LatencyMs"`
	P95LatencyMs     float64 `json:"p95LatencyMs"`
	P99LatencyMs     float64 `json:"p99LatencyMs"`
	InFlightTotal    float64 `json:"inFlightTotal"`
	BytesInTotal     float64 `json:"bytesInTotal"`
	BytesOutTotal    float64 `json:"bytesOutTotal"`
	ActiveConnTotal  float64 `json:"activeConnTotal"`
	RequestsToday    uint64  `json:"requestsToday"`
	BytesToday       uint64  `json:"bytesToday"`
	OpenCircuits     float64 `json:"openCircuits"`
	HalfOpenCircuits float64 `json:"halfOpenCircuits"`
	HealthyTargets   float64 `json:"healthyTargets"`
	TotalTargets     float64 `json:"totalTargets"`
}

// RouteMetric holds per-route request metrics.
type RouteMetric struct {
	Route       string             `json:"route"`
	Service     string             `json:"service"`
	Requests    float64            `json:"requests"`
	Errors      float64            `json:"errors"`
	ErrorRate   float64            `json:"errorRate"`
	AvgLatency  float64            `json:"avgLatencyMs"`
	InFlight    float64            `json:"inFlight"`
	BytesIn     float64            `json:"bytesIn"`
	BytesOut    float64            `json:"bytesOut"`
	StatusCodes map[string]float64 `json:"statusCodes,omitzero"`
	Failures    []LabeledCount     `json:"failures,omitzero"`
}

// MiddlewareMetrics holds counters for all middleware instrumentation.
type MiddlewareMetrics struct {
	RateLimitRejected []LabeledCount `json:"rateLimitRejected,omitzero"`
	WAFBlocked        []LabeledCount `json:"wafBlocked,omitzero"`

	// WAFWouldBlock is what an audit-only WAF declined to refuse, by rule.
	//
	// This is the number an operator needs before enforcing, and until it was
	// surfaced there was no way to get it: audit-only produced a 200 and a
	// threat-list entry, and nothing anywhere said how many real users would have
	// seen a block page. Deployments therefore either enforced blind or left
	// detection on forever.
	//
	// Read it against WAFBlocked: if this is non-empty the route is in audit-only,
	// and every entry is a refusal that would happen the moment it is not.
	WAFWouldBlock      []LabeledCount `json:"wafWouldBlock,omitzero"`
	FastPathBlocked    []LabeledCount `json:"fastPathBlocked,omitzero"`
	CacheHits          float64        `json:"cacheHits"`
	CacheMisses        float64        `json:"cacheMisses"`
	CacheHitRate       float64        `json:"cacheHitRate"`
	AuthFailures       []LabeledCount `json:"authFailures,omitzero"`
	CompressBytesIn    float64        `json:"compressBytesIn"`
	CompressBytesOut   float64        `json:"compressBytesOut"`
	CompressionRatio   float64        `json:"compressionRatio"`
	TurnstilePass      float64        `json:"turnstilePass"`
	TurnstileFail      float64        `json:"turnstileFail"`
	GeoIPBlocked       []LabeledCount `json:"geoipBlocked,omitzero"`
	HMACFailures       float64        `json:"hmacFailures"`
	RetriesSuccess     float64        `json:"retriesSuccess"`
	RetriesFailure     float64        `json:"retriesFailure"`
	ConfigReloads      float64        `json:"configReloads"`
	CacheInvalidations float64        `json:"cacheInvalidations"`
	MitigatedThreats   []LabeledCount `json:"mitigatedThreats,omitzero"`
	BotMitigations     []LabeledCount `json:"botMitigations,omitzero"`
	EbpfDroppedPackets []LabeledCount `json:"ebpfDroppedPackets,omitzero"`
}

// LabeledCount is a metric value with a descriptive label.
type LabeledCount struct {
	Label   string  `json:"label"`
	Value   float64 `json:"value"`
	Subtext string  `json:"subtext,omitempty"`
}

// TLSCertMetric holds certificate expiry information.
type TLSCertMetric struct {
	Domain      string  `json:"domain"`
	CertName    string  `json:"certName"`
	ExpiryEpoch float64 `json:"expiryEpoch"`
	DaysRemain  float64 `json:"daysRemaining"`
}

// TargetMetric holds target health and connection info.
type TargetMetric struct {
	Route      string  `json:"route"`
	Target     string  `json:"target"`
	Healthy    bool    `json:"healthy"`
	ActiveConn float64 `json:"activeConn"`
}

// DomainMetric holds per-domain request metrics.
type DomainMetric struct {
	Domain   string  `json:"domain"`
	Requests float64 `json:"requests"`
	BytesIn  float64 `json:"bytesIn"`
	BytesOut float64 `json:"bytesOut"`
}

// IPMetric holds metrics per IP.
type IPMetric struct {
	IP       string  `json:"ip"`
	Requests float64 `json:"requests"`
	BytesIn  float64 `json:"bytesIn"`
	BytesOut float64 `json:"bytesOut"`
}

// CountryMetric holds metrics per country.
type CountryMetric struct {
	Country     string  `json:"country"`
	CountryName string  `json:"countryName"`
	Requests    float64 `json:"requests"`
	BytesIn     float64 `json:"bytesIn"`
	BytesOut    float64 `json:"bytesOut"`
}

// SystemMetrics holds system-level gauge values.
type SystemMetrics struct {
	UptimeSeconds            float64 `json:"uptimeSeconds"`
	Goroutines               float64 `json:"goroutines"`
	MemoryAllocBytes         float64 `json:"memoryAllocBytes"`
	MemoryTotalBytes         float64 `json:"memoryTotalAllocBytes"`
	MemorySysBytes           float64 `json:"memorySysBytes"`
	CPUUsage                 float64 `json:"cpuUsagePercent"`
	MemoryUsage              float64 `json:"memoryUsagePercent"`
	CPUCores                 int     `json:"cpuCores"`
	MemoryTotalGB            float64 `json:"memoryTotalGB"`
	StorageUsageGB           float64 `json:"storageUsageGB"`
	StorageTotalGB           float64 `json:"storageTotalGB"`
	StorageUsagePct          float64 `json:"storageUsagePercent"`
	PublicIP                 string  `json:"publicIp"`
	Status                   string  `json:"status"`
	Version                  string  `json:"version"`
	TitanEnabled             bool    `json:"titanEnabled"`
	NeuralSentinelEnabled    bool    `json:"neuralSentinelEnabled"`
	GraphIntelligenceEnabled bool    `json:"graphIntelligenceEnabled"`
	PredictiveAiEnabled      bool    `json:"predictiveAiEnabled"`
	PqcEnabled               bool    `json:"pqcEnabled"`
	TpmEnabled               bool    `json:"tpmEnabled"`
	ResourceGovernorEnabled  bool    `json:"resourceGovernorEnabled"`
}

// CollectMetricsSnapshot gathers all registered Prometheus metrics into a structured snapshot.
// It returns a cached snapshot if available and the request matches default parameters.
func CollectMetricsSnapshot(ctx context.Context, limit, offset int) (*MetricsSnapshot, error) {
	if limit == 50 && offset == 0 {
		if snap := lastSnapshot.Load(); snap != nil {
			return snap, nil
		}
	}

	// Fallback to synchronous collection if no cache or non-default parameters
	return collectMetricsSnapshot(ctx, limit, offset, true)
}

func collectMetricsSnapshot(ctx context.Context, limit, offset int, heavy bool) (*MetricsSnapshot, error) {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return nil, err
	}

	idx := make(map[string]*dto.MetricFamily, len(families))
	for _, f := range families {
		idx[f.GetName()] = f
	}

	snap := &MetricsSnapshot{}

	// Capture previous snapshot to preserve heavy data during light refreshes
	prev := lastSnapshot.Load()

	snap.GoldenSignals = buildGoldenSignals(ctx, idx)
	snap.RouteMetrics = buildRouteMetrics(idx)
	snap.Middleware = buildMiddlewareMetrics(idx)
	snap.TLSCertificates = buildTLSCertMetrics(idx)
	snap.Targets = buildTargetMetrics(idx)
	snap.IPMetrics = buildIPMetrics(idx)
	snap.CountryMetrics = buildCountryMetrics(idx)
	snap.ProtocolMetrics = collectLabeledCounts(idx, "gateon_requests_by_protocol_total", "protocol")
	snap.DomainMetrics = buildDomainMetrics(idx)

	if heavy {
		snap.HourlyDomainMetrics = GetDomainStatsWindow(ctx, 1)
		snap.DomainStatsRolling24h = GetDomainStatsRolling24h(ctx)
		snap.TrafficHistory = GetSystemTrafficHistory(ctx, dashboardTrendWindowDays())
		snap.Security = buildSecurityInsights(ctx, idx, limit, offset, true)
	} else if prev != nil {
		snap.HourlyDomainMetrics = prev.HourlyDomainMetrics
		snap.DomainStatsRolling24h = prev.DomainStatsRolling24h
		snap.TrafficHistory = prev.TrafficHistory
		snap.Security = buildSecurityInsights(ctx, idx, limit, offset, false)
		// Merge recent anomalies and total from prev if available
		snap.Security.RecentAnomalies = prev.Security.RecentAnomalies
		snap.Security.TotalAnomalies = prev.Security.TotalAnomalies
		snap.Security.TopThreatSources = prev.Security.TopThreatSources
		snap.Security.TopThreatTypes = prev.Security.TopThreatTypes
		snap.Security.ThreatsByCountry = prev.Security.ThreatsByCountry
		snap.Security.AttackTrend = prev.Security.AttackTrend
	}

	snap.System = buildSystemMetrics(idx)

	if heavy {
		if val := globalEbpfManager.Load(); val != nil {
			if container, ok := val.(*ebpfProviderContainer); ok && container.p != nil {
				if ips, err := container.p.GetTopIPs(5); err == nil {
					converted := make([]IPStat, len(ips))
					for i, ip := range ips {
						converted[i] = IPStat{IP: ip.IP, Count: ip.Count}
					}
					snap.Security.EbpfTopIPs = converted
				}
			}
		}
	} else if prev != nil {
		snap.Security.EbpfTopIPs = prev.Security.EbpfTopIPs
	}

	snap.MitigationFunnel = buildMitigationFunnel(idx)

	// Build active threat metrics
	snap.ActiveSuspiciousSessions = gaugeValue(idx, "gateon_active_suspicious_sessions_total")
	snap.ActiveUnverifiedClients = gaugeValue(idx, "gateon_active_unverified_clients_total")
	snap.ActiveShunnedEntities = collectLabeledCounts(idx, "gateon_active_shunned_entities_total", "type")

	if fam, ok := idx["gateon_active_anomaly_score_average"]; ok {
		if m := fam.GetMetric(); len(m) > 0 {
			snap.ActiveAnomalyScoreAverage = SafeFloat(m[0].GetGauge().GetValue())
		}
	}

	return snap, nil
}

func buildGoldenSignals(ctx context.Context, idx map[string]*dto.MetricFamily) GoldenSignals {
	// Golden signals represent total traffic through the gateway: every series
	// of the per-route families, each request being in exactly one -- its
	// route's, or "gateon-<entrypoint>" when no route took it (ADR 0061).
	gs := onceScopedSignals(idx)

	// Active connections are tracked per-target, not per-route, so they are
	// summed independently of the request-series filter above.
	gs.ActiveConnTotal = sumGauge(idx, "gateon_active_connections", nil)

	// Populate rolling 24h totals from store
	req24h, bytes24h := GetSystemTrafficRolling24h(ctx)
	gs.RequestsToday = req24h
	gs.BytesToday = bytes24h

	// Circuits and targets, counted the way /v1/diag/agg-stats counts them so
	// that a realtime update does not contradict the page it lands on: a down
	// target is an open circuit, and so is an open route breaker.
	targets := CurrentTargetHealth()
	breakersOpen, breakersHalfOpen := RouteBreakerCounts()
	gs.HealthyTargets = float64(targets.Healthy)
	gs.TotalTargets = float64(targets.Total)
	gs.OpenCircuits = float64(targets.Down + breakersOpen)
	gs.HalfOpenCircuits = float64(breakersHalfOpen)

	return gs
}

// computeGoldenSignals aggregates the request/error/latency/bytes/in-flight
// signals for the subset of series matching the supplied filter.
func computeGoldenSignals(idx map[string]*dto.MetricFamily, match func(*dto.Metric) bool) GoldenSignals {
	gs := GoldenSignals{}

	gs.RequestsTotal = sumCounter(idx, "gateon_requests_total", match)

	// Errors = 5xx status codes
	if fam, ok := idx["gateon_requests_total"]; ok {
		for _, m := range fam.GetMetric() {
			if !match(m) {
				continue
			}
			sc := labelValue(m, "status_code")
			if strings.HasPrefix(sc, "5") {
				gs.ErrorsTotal += m.GetCounter().GetValue()
			}
		}
	}
	if gs.RequestsTotal > 0 {
		gs.ErrorRate = SafeFloat((gs.ErrorsTotal / gs.RequestsTotal) * 100)
	}

	// Latency from histogram
	if fam, ok := idx["gateon_request_duration_seconds"]; ok {
		var totalSum float64
		var totalCount uint64
		for _, m := range fam.GetMetric() {
			if !match(m) {
				continue
			}
			h := m.GetHistogram()
			totalSum += h.GetSampleSum()
			totalCount += h.GetSampleCount()
		}
		if totalCount > 0 {
			gs.AvgLatencyMs = SafeFloat((totalSum / float64(totalCount)) * 1000)
		}
		p := estimatePercentiles(fam, []float64{0.50, 0.95, 0.99}, match)
		gs.P50LatencyMs = SafeFloat(p[0] * 1000)
		gs.P95LatencyMs = SafeFloat(p[1] * 1000)
		gs.P99LatencyMs = SafeFloat(p[2] * 1000)
	}

	gs.InFlightTotal = sumGauge(idx, "gateon_requests_in_flight", match)

	if fam, ok := idx["gateon_request_bytes_total"]; ok {
		for _, m := range fam.GetMetric() {
			if !match(m) {
				continue
			}
			dir := labelValue(m, "direction")
			switch dir {
			case "in":
				gs.BytesInTotal += m.GetCounter().GetValue()
			case "out":
				gs.BytesOutTotal += m.GetCounter().GetValue()
			}
		}
	}

	return gs
}

// buildMitigationFunnel counts each request once, by outcome, and attributes
// the refusals to the stage that made them. See MitigationFunnel.
func buildMitigationFunnel(idx map[string]*dto.MetricFamily) MitigationFunnel {
	f := MitigationFunnel{
		Allowed:           outcomeCount(idx, OutcomeForwarded),
		Refused:           outcomeCount(idx, OutcomeRefused),
		Answered:          outcomeCount(idx, OutcomeAnswered),
		ServerErrors:      onceScopedSignals(idx).ErrorsTotal,
		XDPPacketsDropped: sumCounter(idx, "gateon_ebpf_dropped_packets_total", nil),
	}
	f.HTTPIngress = f.Allowed + f.Refused + f.Answered
	f.TotalMitigated = f.Refused
	addFunnelStages(idx, &f)

	stages := f.WAFBlocked + f.FastPathBlocked + f.RateLimited + f.GeoIPBlocked +
		f.AuthFailures + f.TurnstileFailures + f.HMACFailures + f.BotBlocked +
		f.FileSecurityBlocked + f.DeceptionBlocked + f.MitigationBlocked + f.AdvancedSecurityBlock
	f.OtherRefused = max(f.Refused-stages, 0)
	return f
}

// Threat types of a request refused because its source is blocked: the
// address is shunned, or the client build is blocked on its network.
const (
	typeIPMitigation   = "ip_mitigation"
	typeUserMitigation = "user_mitigation"
)

// mitigationThreatTypes are the advanced-security series that are a blocked
// source (a shunned address, a blocked client build) rather than a check.
var mitigationThreatTypes = map[string]bool{typeIPMitigation: true, typeUserMitigation: true, "ip_shunning": true}

// addFunnelStages fills the per-control refusal counts.
func addFunnelStages(idx map[string]*dto.MetricFamily, f *MitigationFunnel) {
	// The "restored" series re-adds the persisted WAF blocks of earlier runs at
	// startup, for the WAF page; the funnel's baseline starts at this run.
	f.WAFBlocked = sumCounter(idx, "gateon_middleware_waf_blocked_total", func(m *dto.Metric) bool {
		return labelValue(m, "rule_id") != "restored"
	})
	f.FastPathBlocked = sumCounter(idx, "gateon_middleware_fast_path_blocked_total", nil)
	f.RateLimited = sumCounter(idx, "gateon_middleware_ratelimit_rejected_total", nil)
	f.GeoIPBlocked = sumCounter(idx, "gateon_middleware_geoip_blocked_total", nil)
	f.AuthFailures = sumCounter(idx, "gateon_middleware_auth_failures_total", nil)
	f.HMACFailures = sumCounter(idx, "gateon_middleware_hmac_failures_total", nil)
	f.FileSecurityBlocked = sumCounter(idx, "gateon_middleware_file_security_blocked_total", nil)
	f.DeceptionBlocked = sumCounter(idx, "gateon_middleware_deception_blocked_total", nil)
	f.MitigationBlocked = sumCounter(idx, "gateon_middleware_advanced_security_blocked_total", func(m *dto.Metric) bool {
		return mitigationThreatTypes[labelValue(m, "threat_type")]
	})
	f.AdvancedSecurityBlock = sumCounter(idx, "gateon_middleware_advanced_security_blocked_total", func(m *dto.Metric) bool {
		return !mitigationThreatTypes[labelValue(m, "threat_type")]
	})
	f.BotBlocked = sumCounter(idx, "gateon_middleware_bot_management_total", func(m *dto.Metric) bool {
		return botRefusal(labelValue(m, "outcome"))
	})
	f.TurnstileFailures = sumCounter(idx, "gateon_middleware_turnstile_total", func(m *dto.Metric) bool {
		return labelValue(m, "outcome") == "fail"
	})
}

// botRefusal reports whether a bot-management outcome is a request it
// refused: a challenge page served in place of the response (403, whatever the
// challenge -- "challenge_served", "pow_challenge_served"), or a block the
// threat pipeline recorded for a failed check or a wrong answer ("blocked").
// The funnel used to count "integrity_failed" and "challenge_failed",
// which nothing records, and missed the served challenges.
func botRefusal(outcome string) bool {
	return outcome == ActionBlocked || strings.HasSuffix(outcome, "challenge_served")
}

// outcomeCount reads one series of gateon_request_outcomes_total.
func outcomeCount(idx map[string]*dto.MetricFamily, outcome string) float64 {
	return sumCounter(idx, "gateon_request_outcomes_total", func(m *dto.Metric) bool {
		return labelValue(m, "outcome") == outcome
	})
}

// onceScopedSignals are the request signals with each request counted once.
//
// The per-route families hold every request exactly once: under its route, or
// under "gateon-<entrypoint>" when no route took it. They used to hold every
// proxied request twice -- the entrypoint's metrics recorded it under
// "gateon-<entrypoint>" as well -- so this read the "gateon-" series alone,
// and anyone summing the families in Prometheus counted double (OPS-N8, ADR
// 0061).
//
// In-flight is the exception: a request a route is serving is also one its
// entrypoint is serving, so the total is the entrypoint gauge's, and the
// route gauge's only where no entrypoint reports.
func onceScopedSignals(idx map[string]*dto.MetricFamily) GoldenSignals {
	gs := computeGoldenSignals(idx, func(m *dto.Metric) bool {
		return labelValue(m, "route") != ""
	})
	if _, ok := idx["gateon_entrypoint_requests_in_flight"]; ok {
		gs.InFlightTotal = sumGauge(idx, "gateon_entrypoint_requests_in_flight", nil)
	}
	return gs
}

// forEachRouteMetric walks one metric family and hands each sample to fn along
// with the RouteMetric it belongs to.
//
// The guard it centralises matters more than the boilerplate it removes: every
// caller has to skip Gateon's own "gateon-" management routes, or the dashboard
// starts reporting the gateway's own control plane as customer traffic. That
// check was written out once per family, so adding a sixth family meant
// remembering it again.
func forEachRouteMetric(
	idx map[string]*dto.MetricFamily,
	family string,
	routeMap map[string]*RouteMetric,
	fn func(rm *RouteMetric, m *dto.Metric),
) {
	fam, ok := idx[family]
	if !ok {
		return
	}
	for _, m := range fam.GetMetric() {
		route := labelValue(m, "route")
		if route == "" || strings.HasPrefix(route, internalRoutePrefix) {
			continue
		}
		fn(getOrCreateRoute(routeMap, route), m)
	}
}

func buildRouteMetrics(idx map[string]*dto.MetricFamily) []RouteMetric {
	routeMap := make(map[string]*RouteMetric)

	forEachRouteMetric(idx, "gateon_requests_total", routeMap, func(rm *RouteMetric, m *dto.Metric) {
		if svc := labelValue(m, "service"); svc != "" {
			rm.Service = svc
		}
		sc := labelValue(m, "status_code")
		val := m.GetCounter().GetValue()
		rm.Requests += val
		rm.StatusCodes[sc] += val
		if strings.HasPrefix(sc, "5") {
			rm.Errors += val
		}
	})

	forEachRouteMetric(idx, "gateon_requests_in_flight", routeMap, func(rm *RouteMetric, m *dto.Metric) {
		rm.InFlight = m.GetGauge().GetValue()
	})

	forEachRouteMetric(idx, "gateon_request_bytes_total", routeMap, func(rm *RouteMetric, m *dto.Metric) {
		val := m.GetCounter().GetValue()
		switch labelValue(m, "direction") {
		case "in":
			rm.BytesIn += val
		case "out":
			rm.BytesOut += val
		}
	})

	forEachRouteMetric(idx, "gateon_request_duration_seconds", routeMap, func(rm *RouteMetric, m *dto.Metric) {
		h := m.GetHistogram()
		if h.GetSampleCount() > 0 {
			rm.AvgLatency = SafeFloat((h.GetSampleSum() / float64(h.GetSampleCount())) * 1000)
		}
	})

	forEachRouteMetric(idx, "gateon_request_failures_total", routeMap, func(rm *RouteMetric, m *dto.Metric) {
		if val := m.GetCounter().GetValue(); val > 0 {
			rm.Failures = append(rm.Failures, LabeledCount{Label: labelValue(m, "reason"), Value: val})
		}
	})

	result := make([]RouteMetric, 0, len(routeMap))
	for _, rm := range routeMap {
		if rm.Requests > 0 {
			rm.ErrorRate = (rm.Errors / rm.Requests) * 100
		}
		result = append(result, *rm)
	}
	return result
}

func buildMiddlewareMetrics(idx map[string]*dto.MetricFamily) MiddlewareMetrics {
	mm := MiddlewareMetrics{}

	mm.RateLimitRejected = collectLabeledCounts(idx, "gateon_middleware_ratelimit_rejected_total", "limiter_type")
	mm.WAFBlocked = collectLabeledCounts(idx, "gateon_middleware_waf_blocked_total", "rule_id")
	mm.WAFWouldBlock = collectLabeledCounts(idx, "gateon_middleware_waf_would_block_total", "rule_id")
	mm.FastPathBlocked = collectLabeledCounts(idx, "gateon_middleware_fast_path_blocked_total", "check_type")
	mm.CacheHits = sumCounter(idx, "gateon_middleware_cache_hits_total", nil)
	mm.CacheMisses = sumCounter(idx, "gateon_middleware_cache_misses_total", nil)
	total := mm.CacheHits + mm.CacheMisses
	if total > 0 {
		mm.CacheHitRate = SafeFloat((mm.CacheHits / total) * 100)
	}
	mm.AuthFailures = collectLabeledCounts(idx, "gateon_middleware_auth_failures_total", "auth_type")
	mm.CompressBytesIn = sumCounter(idx, "gateon_middleware_compress_bytes_in_total", nil)
	mm.CompressBytesOut = sumCounter(idx, "gateon_middleware_compress_bytes_out_total", nil)
	if mm.CompressBytesIn > 0 {
		mm.CompressionRatio = SafeFloat((1 - mm.CompressBytesOut/mm.CompressBytesIn) * 100)
	}

	if fam, ok := idx["gateon_middleware_turnstile_total"]; ok {
		for _, m := range fam.GetMetric() {
			outcome := labelValue(m, "outcome")
			val := m.GetCounter().GetValue()
			switch outcome {
			case "pass":
				mm.TurnstilePass += val
			case "fail":
				mm.TurnstileFail += val
			}
		}
	}

	mm.GeoIPBlocked = collectLabeledCounts(idx, "gateon_middleware_geoip_blocked_total", "country")
	mm.HMACFailures = sumCounter(idx, "gateon_middleware_hmac_failures_total", nil)

	mm.MitigatedThreats = collectLabeledCounts(idx, "gateon_mitigated_threats_total", "category")
	mm.BotMitigations = collectLabeledCounts(idx, "gateon_bot_mitigation_total", "signal")
	mm.EbpfDroppedPackets = collectLabeledCounts(idx, "gateon_ebpf_dropped_packets_total", "reason")

	if fam, ok := idx["gateon_retries_total"]; ok {
		for _, m := range fam.GetMetric() {
			outcome := labelValue(m, "outcome")
			val := m.GetCounter().GetValue()
			switch outcome {
			case "success":
				mm.RetriesSuccess += val
			case "failure":
				mm.RetriesFailure += val
			}
		}
	}

	mm.ConfigReloads = sumCounter(idx, "gateon_config_reloads_total", nil)
	mm.CacheInvalidations = sumCounter(idx, "gateon_proxy_cache_invalidations_total", nil)

	return mm
}

func buildTLSCertMetrics(idx map[string]*dto.MetricFamily) []TLSCertMetric {
	fam, ok := idx["gateon_tls_certificate_expiry_seconds"]
	if !ok {
		return nil
	}
	result := make([]TLSCertMetric, 0, len(fam.GetMetric()))
	for _, m := range fam.GetMetric() {
		epoch := m.GetGauge().GetValue()
		if epoch <= 0 {
			continue
		}
		nowSec := float64(time.Now().Unix())
		result = append(result, TLSCertMetric{
			Domain:      labelValue(m, "domain"),
			CertName:    labelValue(m, "cert_name"),
			ExpiryEpoch: epoch,
			DaysRemain:  (epoch - nowSec) / 86400,
		})
	}
	return result
}

func buildTargetMetrics(idx map[string]*dto.MetricFamily) []TargetMetric {
	targMap := make(map[string]*TargetMetric)

	if fam, ok := idx["gateon_target_health"]; ok {
		for _, m := range fam.GetMetric() {
			route := labelValue(m, "route")
			target := labelValue(m, "target")
			key := route + "|" + target
			tm := &TargetMetric{
				Route:   route,
				Target:  target,
				Healthy: m.GetGauge().GetValue() >= 1,
			}
			targMap[key] = tm
		}
	}

	if fam, ok := idx["gateon_active_connections"]; ok {
		for _, m := range fam.GetMetric() {
			target := labelValue(m, "target")
			// Exact target match: substring matching misattributes connections
			// when one target URL is a prefix/substring of another (e.g. a
			// ":80" target inside a ":8080" target).
			for _, tm := range targMap {
				if tm.Target == target {
					tm.ActiveConn = m.GetGauge().GetValue()
				}
			}
		}
	}

	result := make([]TargetMetric, 0, len(targMap))
	for _, tm := range targMap {
		result = append(result, *tm)
	}
	return result
}

func buildIPMetrics(idx map[string]*dto.MetricFamily) []IPMetric {
	ipMap := make(map[string]*IPMetric)

	if fam, ok := idx["gateon_requests_by_ip_total"]; ok {
		for _, m := range fam.GetMetric() {
			ip := labelValue(m, "ip")
			if ip == "" {
				continue
			}
			im := getOrCreateIP(ipMap, ip)
			im.Requests += m.GetCounter().GetValue()
		}
	}

	if fam, ok := idx["gateon_request_bytes_by_ip_total"]; ok {
		for _, m := range fam.GetMetric() {
			ip := labelValue(m, "ip")
			if ip == "" {
				continue
			}
			im := getOrCreateIP(ipMap, ip)
			dir := labelValue(m, "direction")
			val := m.GetCounter().GetValue()
			if dir == "in" {
				im.BytesIn += val
			} else {
				im.BytesOut += val
			}
		}
	}

	result := make([]IPMetric, 0, len(ipMap))
	for _, im := range ipMap {
		result = append(result, *im)
	}

	// Fall back to the bounded in-memory tracker when the opt-in per-IP Prometheus
	// series is disabled (the default), so the "Bandwidth by IP" card still shows data.
	if len(result) == 0 {
		result = getIPBandwidthStats()
	}

	// Sort by requests descending and limit to top 100 to avoid UI/bandwidth issues
	slices.SortFunc(result, func(a, b IPMetric) int {
		return cmp.Compare(b.Requests, a.Requests)
	})
	if len(result) > 100 {
		result = result[:100]
	}

	return result
}

func getOrCreateIP(m map[string]*IPMetric, ip string) *IPMetric {
	if im, ok := m[ip]; ok {
		return im
	}
	im := &IPMetric{IP: ip}
	m[ip] = im
	return im
}

func buildCountryMetrics(idx map[string]*dto.MetricFamily) []CountryMetric {
	countryMap := make(map[string]*CountryMetric)

	if fam, ok := idx["gateon_requests_by_country_total"]; ok {
		for _, m := range fam.GetMetric() {
			country := labelValue(m, "country")
			if country == "" {
				continue
			}
			cm := getOrCreateCountry(countryMap, country)
			cm.Requests += m.GetCounter().GetValue()
		}
	}

	if fam, ok := idx["gateon_request_bytes_by_country_total"]; ok {
		for _, m := range fam.GetMetric() {
			country := labelValue(m, "country")
			if country == "" {
				continue
			}
			cm := getOrCreateCountry(countryMap, country)
			dir := labelValue(m, "direction")
			val := m.GetCounter().GetValue()
			if dir == "in" {
				cm.BytesIn += val
			} else {
				cm.BytesOut += val
			}
		}
	}

	result := make([]CountryMetric, 0, len(countryMap))
	for _, cm := range countryMap {
		result = append(result, *cm)
	}

	// Sort by requests descending
	slices.SortFunc(result, func(a, b CountryMetric) int {
		return cmp.Compare(b.Requests, a.Requests)
	})
	if len(result) > 50 {
		result = result[:50]
	}

	return result
}

func getOrCreateCountry(m map[string]*CountryMetric, country string) *CountryMetric {
	if cm, ok := m[country]; ok {
		return cm
	}
	cm := &CountryMetric{
		Country:     country,
		CountryName: getCountryName(country),
	}
	m[country] = cm
	return cm
}

func buildDomainMetrics(idx map[string]*dto.MetricFamily) []DomainMetric {
	domainMap := make(map[string]*DomainMetric)

	if fam, ok := idx["gateon_requests_by_domain_total"]; ok {
		for _, m := range fam.GetMetric() {
			domain := labelValue(m, "domain")
			if domain == "" {
				continue
			}
			dm := getOrCreateDomain(domainMap, domain)
			dm.Requests += m.GetCounter().GetValue()
		}
	}

	if fam, ok := idx["gateon_request_bytes_by_domain_total"]; ok {
		for _, m := range fam.GetMetric() {
			domain := labelValue(m, "domain")
			if domain == "" {
				continue
			}
			dm := getOrCreateDomain(domainMap, domain)
			dir := labelValue(m, "direction")
			val := m.GetCounter().GetValue()
			if dir == "in" {
				dm.BytesIn += val
			} else {
				dm.BytesOut += val
			}
		}
	}

	result := make([]DomainMetric, 0, len(domainMap))
	for _, dm := range domainMap {
		result = append(result, *dm)
	}

	// Sort by requests descending, then by domain name
	slices.SortFunc(result, func(a, b DomainMetric) int {
		if a.Requests != b.Requests {
			return cmp.Compare(b.Requests, a.Requests)
		}
		return strings.Compare(a.Domain, b.Domain)
	})

	// Limit to top 50 domains
	if len(result) > 50 {
		result = result[:50]
	}

	return result
}

func getOrCreateDomain(m map[string]*DomainMetric, domain string) *DomainMetric {
	if dm, ok := m[domain]; ok {
		return dm
	}
	dm := &DomainMetric{Domain: domain}
	m[domain] = dm
	return dm
}

func buildSystemMetrics(idx map[string]*dto.MetricFamily) SystemMetrics {
	// Uptime is read directly rather than off the gauge. The gauge is only as
	// fresh as the collector's last tick, so this endpoint reported a gateway
	// several seconds younger than /v1/status said it was — for the same
	// process, queried in the same second. Elapsed time is the one figure here
	// that can be computed exactly at any instant, so it is.
	sm := SystemMetrics{
		UptimeSeconds:    GetSystemStats().UptimeSeconds,
		Goroutines:       gaugeValue(idx, "gateon_goroutines"),
		MemoryAllocBytes: gaugeValue(idx, "gateon_memory_alloc_bytes"),
		MemoryTotalBytes: gaugeValue(idx, "gateon_memory_total_alloc_bytes"),
		MemorySysBytes:   gaugeValue(idx, "gateon_memory_sys_bytes"),
		CPUUsage:         gaugeValue(idx, "gateon_cpu_usage_percent"),
		MemoryUsage:      gaugeValue(idx, "gateon_memory_usage_percent"),
		CPUCores:         runtime.NumCPU(),
		Status:           "running",
		Version:          "dev",
	}

	if v := globalVersion.Load(); v != nil {
		sm.Version = v.(string)
	}

	if fam, ok := idx["gateon_memory_sys_bytes"]; ok && len(fam.GetMetric()) > 0 {
		// Total system memory in GB
		if v, err := mem.VirtualMemory(); err == nil {
			sm.MemoryTotalGB = float64(v.Total) / (1024 * 1024 * 1024)
		}
	}

	sm.StorageUsageGB = gaugeValue(idx, "gateon_storage_usage_bytes") / (1024 * 1024 * 1024)
	sm.StorageTotalGB = gaugeValue(idx, "gateon_storage_total_bytes") / (1024 * 1024 * 1024)
	sm.StorageUsagePct = gaugeValue(idx, "gateon_storage_usage_percent")
	sm.PublicIP = GetPublicIP(context.Background())

	// Feature flags
	sm.TitanEnabled = false
	if v := globalTitan.Load(); v != nil {
		if container, ok := v.(*titanProviderContainer); ok && container.p != nil {
			enabled, _, _ := container.p.GetStatus()
			sm.TitanEnabled = enabled
		}
	}

	sm.PredictiveAiEnabled = ai.GlobalPredictor() != nil
	sm.NeuralSentinelEnabled, sm.GraphIntelligenceEnabled = detectorStatus()
	sm.PqcEnabled = true // ML-KEM/ML-DSA always available in binary

	sm.ResourceGovernorEnabled = false
	if v := globalGovernor.Load(); v != nil {
		if container, ok := v.(*governorProviderContainer); ok && container.p != nil {
			active, _, _, _, _ := container.p.GetStatus(context.Background())
			sm.ResourceGovernorEnabled = active
		}
	}

	return sm
}

func buildSecurityInsights(ctx context.Context, idx map[string]*dto.MetricFamily, limit, offset int, heavy bool) SecurityInsights {
	// Parallelize database queries to minimize latency on the metrics path.
	var (
		threats     []*SecurityThreat
		total       int64
		activeCount int
		mitigated   int
		sources     []LabeledCount
		types       []LabeledCount
		byCountry   []LabeledCount
		trend       []TrafficSample
	)

	g, ctx := errgroup.WithContext(ctx)

	if heavy {
		g.Go(func() error {
			threats = GetSecurityThreatsLite(ctx, limit, offset, nil)
			return nil
		})
		g.Go(func() error {
			total = CountSecurityThreats(ctx, nil)
			return nil
		})
		g.Go(func() error {
			sources = GetTopThreatSources(ctx, 5)
			return nil
		})
		g.Go(func() error {
			types = GetTopThreatTypes(ctx, 5)
			return nil
		})
		g.Go(func() error {
			byCountry = GetThreatsByCountry(ctx, 10)
			return nil
		})
		g.Go(func() error {
			trend = GetAttackTrend(ctx, dashboardTrendWindowDays())
			return nil
		})
	}

	// Always refresh atomic counters (low cost)
	g.Go(func() error {
		activeCount = GetActiveThreatsRolling24h(ctx)
		return nil
	})
	g.Go(func() error {
		mitigated = GetMitigatedRolling24h(ctx)
		return nil
	})

	_ = g.Wait()

	return SecurityInsights{
		TopThreatSources:  sources,
		TopThreatTypes:    types,
		ThreatsByCountry:  byCountry,
		AttackTrend:       trend,
		RecentAnomalies:   threats,
		TotalAnomalies:    total,
		ActiveThreats:     activeCount,
		MitigatedToday:    mitigated,
		HeavyHitters:      GlobalHHH.GetHeavyHitters(10), // Threshold of 10 threat events
		GlobalThreatScore: float64(GlobalCMS.Estimate("global")),
		EbpfTopIPs:        nil, // Filled by caller
	}
}

// --- helpers ---

func getOrCreateRoute(m map[string]*RouteMetric, route string) *RouteMetric {
	if rm, ok := m[route]; ok {
		return rm
	}
	rm := &RouteMetric{
		Route:       route,
		StatusCodes: make(map[string]float64),
		Failures:    make([]LabeledCount, 0),
	}
	m[route] = rm
	return rm
}

func labelValue(m *dto.Metric, name string) string {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

func sumCounter(idx map[string]*dto.MetricFamily, name string, filter func(*dto.Metric) bool) float64 {
	fam, ok := idx[name]
	if !ok {
		return 0
	}
	var total float64
	for _, m := range fam.GetMetric() {
		if filter != nil && !filter(m) {
			continue
		}
		total += m.GetCounter().GetValue()
	}
	return total
}

func sumGauge(idx map[string]*dto.MetricFamily, name string, filter func(*dto.Metric) bool) float64 {
	fam, ok := idx[name]
	if !ok {
		return 0
	}
	var total float64
	for _, m := range fam.GetMetric() {
		if filter != nil && !filter(m) {
			continue
		}
		total += m.GetGauge().GetValue()
	}
	return total
}

func gaugeValue(idx map[string]*dto.MetricFamily, name string) float64 {
	fam, ok := idx[name]
	if !ok {
		return 0
	}
	metrics := fam.GetMetric()
	if len(metrics) == 0 {
		return 0
	}
	return metrics[0].GetGauge().GetValue()
}

func collectLabeledCounts(idx map[string]*dto.MetricFamily, name, labelName string) []LabeledCount {
	fam, ok := idx[name]
	if !ok {
		return nil
	}
	agg := make(map[string]float64)
	for _, m := range fam.GetMetric() {
		lbl := labelValue(m, labelName)
		if lbl == "" {
			lbl = "unknown"
		}

		// Include route if present
		route := labelValue(m, "route")
		if route != "" {
			lbl = route + ": " + lbl
		}

		agg[lbl] += m.GetCounter().GetValue()
	}
	result := make([]LabeledCount, 0, len(agg))
	for label, val := range agg {
		if val > 0 {
			result = append(result, LabeledCount{Label: label, Value: val})
		}
	}

	// Sort by value descending
	slices.SortFunc(result, func(a, b LabeledCount) int {
		return cmp.Compare(b.Value, a.Value)
	})

	return result
}

// estimatePercentiles estimates multiple percentiles from a histogram in one pass.
func estimatePercentiles(fam *dto.MetricFamily, quantiles []float64, filter func(*dto.Metric) bool) []float64 {
	results := make([]float64, len(quantiles))
	var totalCount uint64
	for _, m := range fam.GetMetric() {
		if filter != nil && !filter(m) {
			continue
		}
		totalCount += m.GetHistogram().GetSampleCount()
	}
	if totalCount == 0 {
		return results
	}

	type bkt struct {
		upperBound      float64
		cumulativeCount uint64
	}
	bucketMap := make(map[float64]uint64)
	for _, m := range fam.GetMetric() {
		if filter != nil && !filter(m) {
			continue
		}
		for _, b := range m.GetHistogram().GetBucket() {
			bucketMap[b.GetUpperBound()] += b.GetCumulativeCount()
		}
	}

	buckets := make([]bkt, 0, len(bucketMap))
	for ub, cc := range bucketMap {
		buckets = append(buckets, bkt{upperBound: ub, cumulativeCount: cc})
	}

	slices.SortFunc(buckets, func(a, b bkt) int {
		return cmp.Compare(a.upperBound, b.upperBound)
	})

	for i, q := range quantiles {
		target := q * float64(totalCount)
		var prevBound float64
		var prevCount uint64
		found := false
		for _, b := range buckets {
			if float64(b.cumulativeCount) >= target {
				countInBucket := float64(b.cumulativeCount - prevCount)
				if countInBucket <= 0 {
					results[i] = b.upperBound
				} else {
					fraction := (target - float64(prevCount)) / countInBucket
					results[i] = prevBound + fraction*(b.upperBound-prevBound)
				}
				found = true
				break
			}
			prevBound = b.upperBound
			prevCount = b.cumulativeCount
		}
		if !found && len(buckets) > 0 {
			results[i] = buckets[len(buckets)-1].upperBound
		}
	}

	return results
}

// GetServiceGoldenSignals returns golden signals for a specific service.
func GetServiceGoldenSignals(ctx context.Context, serviceID string) GoldenSignals {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return GoldenSignals{}
	}

	idx := make(map[string]*dto.MetricFamily, len(families))
	for _, f := range families {
		idx[f.GetName()] = f
	}

	isService := func(m *dto.Metric) bool {
		return labelValue(m, "service") == serviceID
	}

	gs := GoldenSignals{}
	gs.RequestsTotal = sumCounter(idx, "gateon_requests_total", isService)

	// Errors = 5xx status codes
	if fam, ok := idx["gateon_requests_total"]; ok {
		for _, m := range fam.GetMetric() {
			if !isService(m) {
				continue
			}
			sc := labelValue(m, "status_code")
			if strings.HasPrefix(sc, "5") {
				gs.ErrorsTotal += m.GetCounter().GetValue()
			}
		}
	}
	if gs.RequestsTotal > 0 {
		gs.ErrorRate = SafeFloat((gs.ErrorsTotal / gs.RequestsTotal) * 100)
	}

	// Latency from histogram
	if fam, ok := idx["gateon_request_duration_seconds"]; ok {
		var totalSum float64
		var totalCount uint64
		for _, m := range fam.GetMetric() {
			if !isService(m) {
				continue
			}
			h := m.GetHistogram()
			totalSum += h.GetSampleSum()
			totalCount += h.GetSampleCount()
		}
		if totalCount > 0 {
			gs.AvgLatencyMs = SafeFloat((totalSum / float64(totalCount)) * 1000)
		}
		p := estimatePercentiles(fam, []float64{0.50, 0.95, 0.99}, isService)
		gs.P50LatencyMs = SafeFloat(p[0] * 1000)
		gs.P95LatencyMs = SafeFloat(p[1] * 1000)
		gs.P99LatencyMs = SafeFloat(p[2] * 1000)
	}

	gs.InFlightTotal = sumGauge(idx, "gateon_requests_in_flight", isService)

	if fam, ok := idx["gateon_request_bytes_total"]; ok {
		for _, m := range fam.GetMetric() {
			if !isService(m) {
				continue
			}
			dir := labelValue(m, "direction")
			switch dir {
			case "in":
				gs.BytesInTotal += m.GetCounter().GetValue()
			case "out":
				gs.BytesOutTotal += m.GetCounter().GetValue()
			}
		}
	}

	return gs
}
