// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package telemetry

import (
	"cmp"
	"context"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/sync/errgroup"
)

type EbpfProvider interface {
	GetTopIPs(limit int) ([]IPStat, error)
	ShunIP(ip string) error
	UnshunIP(ip string) error
	SetAdaptiveRateLimit(ip string, interval time.Duration) error
}

var (
	globalEbpfManager atomic.Value // stores EbpfProvider (interface)
	lastSnapshot      atomic.Pointer[MetricsSnapshot]

	snapshotPool = sync.Pool{
		New: func() any {
			return &MetricsSnapshot{}
		},
	}
)

func (s *MetricsSnapshot) Reset() {
	if s == nil {
		return
	}
	// Use reflection or manual clear for complex structs.
	// For now, just re-initialize the slices to reuse capacity.
	s.RouteMetrics = s.RouteMetrics[:0]
	s.TLSCertificates = s.TLSCertificates[:0]
	s.Targets = s.Targets[:0]
	s.IPMetrics = s.IPMetrics[:0]
	s.CountryMetrics = s.CountryMetrics[:0]
	s.ProtocolMetrics = s.ProtocolMetrics[:0]
	s.DomainMetrics = s.DomainMetrics[:0]
	s.HourlyDomainMetrics = s.HourlyDomainMetrics[:0]
	s.DomainStatsRolling24h = s.DomainStatsRolling24h[:0]
	s.TrafficHistory = s.TrafficHistory[:0]
	s.ActiveShunnedEntities = s.ActiveShunnedEntities[:0]
}

func SetEbpfManager(m EbpfProvider) {
	globalEbpfManager.Store(m)
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

			snap, err := collectMetricsSnapshot(ctx, 50, 0, isHeavy)
			if err == nil {
				old := lastSnapshot.Swap(snap)
				if old != nil {
					snapshotPool.Put(old)
				}
			}

			interval := time.Duration(td.TelemetryIntervalSeconds) * time.Second
			if interval <= 0 {
				interval = 5 * time.Second
			}
			timer.Reset(interval)
		}
	}
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

// MitigationFunnel holds a reconciled, single-unit (HTTP request) view of how
// ingress traffic is filtered by each security layer. The invariant
//
//	Allowed + TotalMitigated == HTTPIngress
//
// holds by construction. All inputs share one scope: the request baseline and
// each mitigation counter are summed unfiltered across every label, so they are
// directly comparable (the previous frontend math mixed an entrypoint-scoped
// request total with all-route block counters). ServerErrors (5xx of allowed
// traffic) and XDPPacketsDropped (packets dropped below the HTTP layer, a
// different unit) are reported separately and are NOT funnel stages.
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
	AdvancedSecurityBlock float64 `json:"advancedSecurityBlocked"`
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
	RequestsTotal   float64 `json:"requestsTotal"`
	ErrorsTotal     float64 `json:"errorsTotal"`
	ErrorRate       float64 `json:"errorRate"`
	AvgLatencyMs    float64 `json:"avgLatencyMs"`
	P50LatencyMs    float64 `json:"p50LatencyMs"`
	P95LatencyMs    float64 `json:"p95LatencyMs"`
	P99LatencyMs    float64 `json:"p99LatencyMs"`
	InFlightTotal   float64 `json:"inFlightTotal"`
	BytesInTotal    float64 `json:"bytesInTotal"`
	BytesOutTotal   float64 `json:"bytesOutTotal"`
	ActiveConnTotal float64 `json:"activeConnTotal"`
	RequestsToday   uint64  `json:"requestsToday"`
	BytesToday      uint64  `json:"bytesToday"`
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
	RateLimitRejected  []LabeledCount `json:"rateLimitRejected,omitzero"`
	WAFBlocked         []LabeledCount `json:"wafBlocked,omitzero"`
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
	UptimeSeconds    float64 `json:"uptimeSeconds"`
	Goroutines       float64 `json:"goroutines"`
	MemoryAllocBytes float64 `json:"memoryAllocBytes"`
	MemoryTotalBytes float64 `json:"memoryTotalAllocBytes"`
	MemorySysBytes   float64 `json:"memorySysBytes"`
	CPUUsage         float64 `json:"cpuUsagePercent"`
	MemoryUsage      float64 `json:"memoryUsagePercent"`
	CPUCores         int     `json:"cpuCores"`
	MemoryTotalGB    float64 `json:"memoryTotalGB"`
	StorageUsageGB   float64 `json:"storageUsageGB"`
	StorageTotalGB   float64 `json:"storageTotalGB"`
	StorageUsagePct  float64 `json:"storageUsagePercent"`
	PublicIP         string  `json:"publicIp"`
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

	snap := snapshotPool.Get().(*MetricsSnapshot)
	snap.Reset()

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
		if m := globalEbpfManager.Load(); m != nil {
			if prov, ok := m.(EbpfProvider); ok {
				if ips, err := prov.GetTopIPs(5); err == nil {
					snap.Security.EbpfTopIPs = ips
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
	// Golden signals represent total traffic through the gateway. The preferred
	// source is the entrypoint layer ("gateon-" prefixed route label), which
	// counts every request hitting the gateway exactly once (including requests
	// that don't match a user route). If no entrypoint-level series exist — e.g.
	// only a management entrypoint is configured, or a custom label scheme is in
	// use — we fall back to summing the per-route series so the headline signals
	// still reflect real proxied traffic instead of silently showing zero (RC#1).

	// Cache label lookups during filtering
	epFilter := func(m *dto.Metric) bool {
		r := labelValue(m, "route")
		return strings.HasPrefix(r, "gateon-")
	}
	routeFilter := func(m *dto.Metric) bool {
		r := labelValue(m, "route")
		return r != "" && !strings.HasPrefix(r, "gateon-")
	}

	gs := computeGoldenSignals(idx, epFilter)
	if gs.RequestsTotal == 0 {
		if fallback := computeGoldenSignals(idx, routeFilter); fallback.RequestsTotal > 0 {
			gs = fallback
		}
	}

	// Active connections are tracked per-target, not per-route, so they are
	// summed independently of the request-series filter above.
	gs.ActiveConnTotal = sumGauge(idx, "gateon_active_connections", nil)

	// Populate rolling 24h totals from store
	req24h, bytes24h := GetSystemTrafficRolling24h(ctx)
	gs.RequestsToday = req24h
	gs.BytesToday = bytes24h

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

// buildMitigationFunnel produces a reconciled, single-unit view of the security
// mitigation funnel. Unlike the old frontend computation, it uses one consistent
// scope (unfiltered request total + unfiltered block counters) so the stages add
// up exactly: Allowed + TotalMitigated == HTTPIngress.
func buildMitigationFunnel(idx map[string]*dto.MetricFamily) MitigationFunnel {
	// Unfiltered baseline so it shares scope with the all-label block counters.
	allMatch := func(*dto.Metric) bool { return true }
	gs := computeGoldenSignals(idx, allMatch)

	f := MitigationFunnel{
		HTTPIngress:           gs.RequestsTotal,
		WAFBlocked:            sumCounter(idx, "gateon_middleware_waf_blocked_total", nil),
		FastPathBlocked:       sumCounter(idx, "gateon_middleware_fast_path_blocked_total", nil),
		RateLimited:           sumCounter(idx, "gateon_middleware_ratelimit_rejected_total", nil),
		GeoIPBlocked:          sumCounter(idx, "gateon_middleware_geoip_blocked_total", nil),
		AuthFailures:          sumCounter(idx, "gateon_middleware_auth_failures_total", nil),
		HMACFailures:          sumCounter(idx, "gateon_middleware_hmac_failures_total", nil),
		FileSecurityBlocked:   sumCounter(idx, "gateon_middleware_file_security_blocked_total", nil),
		AdvancedSecurityBlock: sumCounter(idx, "gateon_middleware_advanced_security_blocked_total", nil),
		DeceptionBlocked:      sumCounter(idx, "gateon_middleware_deception_blocked_total", nil),
		ServerErrors:          gs.ErrorsTotal,
		XDPPacketsDropped:     sumCounter(idx, "gateon_ebpf_dropped_packets_total", nil),
	}

	// Add Bot Management blocks to the funnel
	if fam, ok := idx["gateon_middleware_bot_management_total"]; ok {
		for _, m := range fam.GetMetric() {
			outcome := labelValue(m, "outcome")
			if outcome == "blocked" || outcome == "integrity_failed" || outcome == "challenge_failed" {
				f.BotBlocked += m.GetCounter().GetValue()
			}
		}
	}

	if fam, ok := idx["gateon_middleware_turnstile_total"]; ok {
		for _, m := range fam.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "outcome" && lp.GetValue() == "fail" {
					f.TurnstileFailures += m.GetCounter().GetValue()
					break
				}
			}
		}
	}

	f.TotalMitigated = f.WAFBlocked + f.FastPathBlocked + f.RateLimited + f.GeoIPBlocked +
		f.AuthFailures + f.TurnstileFailures + f.HMACFailures +
		f.BotBlocked + f.FileSecurityBlocked + f.DeceptionBlocked +
		f.AdvancedSecurityBlock

	// Rejected requests are still counted once in gateon_requests_total (they
	// return a 4xx through the metrics middleware), so subtracting the block
	// counters yields the requests that passed every mitigation. Clamp at zero in
	// case counters were restored/reset out of step across a restart.
	f.Allowed = f.HTTPIngress - f.TotalMitigated
	if f.Allowed < 0 {
		f.Allowed = 0
	}

	return f
}

func buildRouteMetrics(idx map[string]*dto.MetricFamily) []RouteMetric {
	routeMap := make(map[string]*RouteMetric)

	if fam, ok := idx["gateon_requests_total"]; ok {
		for _, m := range fam.GetMetric() {
			route := labelValue(m, "route")
			if route == "" || strings.HasPrefix(route, "gateon-") {
				continue
			}
			rm := getOrCreateRoute(routeMap, route)
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
		}
	}

	if fam, ok := idx["gateon_requests_in_flight"]; ok {
		for _, m := range fam.GetMetric() {
			route := labelValue(m, "route")
			if route == "" || strings.HasPrefix(route, "gateon-") {
				continue
			}
			rm := getOrCreateRoute(routeMap, route)
			rm.InFlight = m.GetGauge().GetValue()
		}
	}

	if fam, ok := idx["gateon_request_bytes_total"]; ok {
		for _, m := range fam.GetMetric() {
			route := labelValue(m, "route")
			if route == "" || strings.HasPrefix(route, "gateon-") {
				continue
			}
			rm := getOrCreateRoute(routeMap, route)
			dir := labelValue(m, "direction")
			val := m.GetCounter().GetValue()
			if dir == "in" {
				rm.BytesIn += val
			} else if dir == "out" {
				rm.BytesOut += val
			}
		}
	}

	if fam, ok := idx["gateon_request_duration_seconds"]; ok {
		for _, m := range fam.GetMetric() {
			route := labelValue(m, "route")
			if route == "" || strings.HasPrefix(route, "gateon-") {
				continue
			}
			rm := getOrCreateRoute(routeMap, route)
			h := m.GetHistogram()
			if h.GetSampleCount() > 0 {
				rm.AvgLatency = SafeFloat((h.GetSampleSum() / float64(h.GetSampleCount())) * 1000)
			}
		}
	}
	if fam, ok := idx["gateon_request_failures_total"]; ok {
		for _, m := range fam.GetMetric() {
			route := labelValue(m, "route")
			if route == "" || strings.HasPrefix(route, "gateon-") {
				continue
			}
			rm := getOrCreateRoute(routeMap, route)
			reason := labelValue(m, "reason")
			val := m.GetCounter().GetValue()
			if val > 0 {
				rm.Failures = append(rm.Failures, LabeledCount{Label: reason, Value: val})
			}
		}
	}

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
	sm := SystemMetrics{
		UptimeSeconds:    gaugeValue(idx, "gateon_uptime_seconds"),
		Goroutines:       gaugeValue(idx, "gateon_goroutines"),
		MemoryAllocBytes: gaugeValue(idx, "gateon_memory_alloc_bytes"),
		MemoryTotalBytes: gaugeValue(idx, "gateon_memory_total_alloc_bytes"),
		MemorySysBytes:   gaugeValue(idx, "gateon_memory_sys_bytes"),
		CPUUsage:         gaugeValue(idx, "gateon_cpu_usage_percent"),
		MemoryUsage:      gaugeValue(idx, "gateon_memory_usage_percent"),
		CPUCores:         runtime.NumCPU(),
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
