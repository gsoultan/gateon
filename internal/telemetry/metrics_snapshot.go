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
	globalEbpfManager atomic.Pointer[EbpfProvider]
	lastSnapshot      atomic.Pointer[MetricsSnapshot]
	snapshotMu        sync.Mutex
)

func SetEbpfManager(m EbpfProvider) {
	globalEbpfManager.Store(&m)
}

// StartSnapshotLoop starts a background goroutine to periodically refresh the
// global metrics snapshot, ensuring the UI remains fast even under load.
func StartSnapshotLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Initial snapshot
	if snap, err := collectMetricsSnapshot(ctx, 50, 0); err == nil {
		lastSnapshot.Store(snap)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap, err := collectMetricsSnapshot(ctx, 50, 0)
			if err == nil {
				lastSnapshot.Store(snap)
			}
		}
	}
}

// MetricsSnapshot holds a structured view of all Prometheus metrics for the UI.
type MetricsSnapshot struct {
	// Golden signals
	GoldenSignals GoldenSignals `json:"golden_signals,omitzero"`

	// Per-route request metrics broken down by status code.
	RouteMetrics []RouteMetric `json:"route_metrics,omitzero"`

	// Middleware counters (rate limit, WAF, cache, auth, compress, turnstile, geoip, hmac).
	Middleware MiddlewareMetrics `json:"middleware,omitzero"`

	// TLS certificate expiry information.
	TLSCertificates []TLSCertMetric `json:"tls_certificates,omitzero"`

	// Target health and connection status.
	Targets []TargetMetric `json:"targets,omitzero"`

	// IP-based metrics
	IPMetrics []IPMetric `json:"ip_metrics,omitzero"`

	// Country-based metrics
	CountryMetrics []CountryMetric `json:"country_metrics,omitzero"`

	// Protocol-based metrics
	ProtocolMetrics []LabeledCount `json:"protocol_metrics,omitzero"`

	// Domain-based metrics
	DomainMetrics []DomainMetric `json:"domain_metrics,omitzero"`

	// Hourly domain metrics (current hour)
	HourlyDomainMetrics []DomainStats `json:"hourly_domain_metrics,omitzero"`

	// Rolling 24h domain metrics
	DomainStatsRolling24h []DomainStats `json:"domain_stats_rolling24h,omitzero"`

	// Traffic history for charts (last 24-48 hours)
	TrafficHistory []TrafficSample `json:"traffic_history,omitzero"`

	// Active threats
	ActiveSuspiciousSessions  float64        `json:"active_suspicious_sessions"`
	ActiveUnverifiedClients   float64        `json:"active_unverified_clients"`
	ActiveShunnedEntities     []LabeledCount `json:"active_shunned_entities,omitzero"`
	ActiveAnomalyScoreAverage float64        `json:"active_anomaly_score_average"`

	// System-level gauges.
	System SystemMetrics `json:"system,omitzero"`

	// Security insights
	Security SecurityInsights `json:"security,omitzero"`

	// Reconciled mitigation funnel (single-unit, server-computed).
	MitigationFunnel MitigationFunnel `json:"mitigation_funnel,omitzero"`
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
	HTTPIngress           float64 `json:"http_ingress"`
	WAFBlocked            float64 `json:"waf_blocked"`
	RateLimited           float64 `json:"rate_limited"`
	GeoIPBlocked          float64 `json:"geoip_blocked"`
	AuthFailures          float64 `json:"auth_failures"`
	TurnstileFailures     float64 `json:"turnstile_failures"`
	HMACFailures          float64 `json:"hmac_failures"`
	BotBlocked            float64 `json:"bot_blocked"`
	FileSecurityBlocked   float64 `json:"file_security_blocked"`
	DeceptionBlocked      float64 `json:"deception_blocked"`
	AdvancedSecurityBlock float64 `json:"advanced_security_blocked"`
	TotalMitigated        float64 `json:"total_mitigated"`
	Allowed               float64 `json:"allowed"`
	ServerErrors          float64 `json:"server_errors"`
	XDPPacketsDropped     float64 `json:"xdp_packets_dropped"`
}

type SecurityInsights struct {
	TopThreatSources  []LabeledCount    `json:"top_threat_sources,omitzero"`
	TopThreatTypes    []LabeledCount    `json:"top_threat_types,omitzero"`
	ThreatsByCountry  []LabeledCount    `json:"threats_by_country,omitzero"`
	AttackTrend       []TrafficSample   `json:"attack_trend,omitzero"`
	RecentAnomalies   []*SecurityThreat `json:"recent_anomalies,omitzero"`
	TotalAnomalies    int64             `json:"total_anomalies"`
	ActiveThreats     int               `json:"active_threats"`
	MitigatedToday    int               `json:"mitigated_today"`
	HeavyHitters      []HeavyHitter     `json:"heavy_hitters,omitzero"`
	GlobalThreatScore float64           `json:"global_threat_score"`
	EbpfTopIPs        []IPStat          `json:"ebpf_top_ips,omitzero"`
}

type IPStat struct {
	IP    string `json:"ip"`
	Count uint64 `json:"count"`
}

// GoldenSignals represents the four golden signals of monitoring.
type GoldenSignals struct {
	RequestsTotal   float64 `json:"requests_total"`
	ErrorsTotal     float64 `json:"errors_total"`
	ErrorRate       float64 `json:"error_rate"`
	AvgLatencyMs    float64 `json:"avg_latency_ms"`
	P50LatencyMs    float64 `json:"p50_latency_ms"`
	P95LatencyMs    float64 `json:"p95_latency_ms"`
	P99LatencyMs    float64 `json:"p99_latency_ms"`
	InFlightTotal   float64 `json:"in_flight_total"`
	BytesInTotal    float64 `json:"bytes_in_total"`
	BytesOutTotal   float64 `json:"bytes_out_total"`
	ActiveConnTotal float64 `json:"active_conn_total"`
	RequestsToday   uint64  `json:"requests_today"`
	BytesToday      uint64  `json:"bytes_today"`
}

// RouteMetric holds per-route request metrics.
type RouteMetric struct {
	Route       string             `json:"route"`
	Service     string             `json:"service"`
	Requests    float64            `json:"requests"`
	Errors      float64            `json:"errors"`
	ErrorRate   float64            `json:"error_rate"`
	AvgLatency  float64            `json:"avg_latency_ms"`
	InFlight    float64            `json:"in_flight"`
	BytesIn     float64            `json:"bytes_in"`
	BytesOut    float64            `json:"bytes_out"`
	StatusCodes map[string]float64 `json:"status_codes,omitzero"`
	Failures    []LabeledCount     `json:"failures,omitzero"`
}

// MiddlewareMetrics holds counters for all middleware instrumentation.
type MiddlewareMetrics struct {
	RateLimitRejected  []LabeledCount `json:"rate_limit_rejected,omitzero"`
	WAFBlocked         []LabeledCount `json:"waf_blocked,omitzero"`
	CacheHits          float64        `json:"cache_hits"`
	CacheMisses        float64        `json:"cache_misses"`
	CacheHitRate       float64        `json:"cache_hit_rate"`
	AuthFailures       []LabeledCount `json:"auth_failures,omitzero"`
	CompressBytesIn    float64        `json:"compress_bytes_in"`
	CompressBytesOut   float64        `json:"compress_bytes_out"`
	CompressionRatio   float64        `json:"compression_ratio"`
	TurnstilePass      float64        `json:"turnstile_pass"`
	TurnstileFail      float64        `json:"turnstile_fail"`
	GeoIPBlocked       []LabeledCount `json:"geoip_blocked,omitzero"`
	HMACFailures       float64        `json:"hmac_failures"`
	RetriesSuccess     float64        `json:"retries_success"`
	RetriesFailure     float64        `json:"retries_failure"`
	ConfigReloads      float64        `json:"config_reloads"`
	CacheInvalidations float64        `json:"cache_invalidations"`
	MitigatedThreats   []LabeledCount `json:"mitigated_threats,omitzero"`
	BotMitigations     []LabeledCount `json:"bot_mitigations,omitzero"`
	EbpfDroppedPackets []LabeledCount `json:"ebpf_dropped_packets,omitzero"`
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
	CertName    string  `json:"cert_name"`
	ExpiryEpoch float64 `json:"expiry_epoch"`
	DaysRemain  float64 `json:"days_remaining"`
}

// TargetMetric holds target health and connection info.
type TargetMetric struct {
	Route      string  `json:"route"`
	Target     string  `json:"target"`
	Healthy    bool    `json:"healthy"`
	ActiveConn float64 `json:"active_conn"`
}

// DomainMetric holds per-domain request metrics.
type DomainMetric struct {
	Domain   string  `json:"domain"`
	Requests float64 `json:"requests"`
	BytesIn  float64 `json:"bytes_in"`
	BytesOut float64 `json:"bytes_out"`
}

// IPMetric holds metrics per IP.
type IPMetric struct {
	IP       string  `json:"ip"`
	Requests float64 `json:"requests"`
	BytesIn  float64 `json:"bytes_in"`
	BytesOut float64 `json:"bytes_out"`
}

// CountryMetric holds metrics per country.
type CountryMetric struct {
	Country     string  `json:"country"`
	CountryName string  `json:"country_name"`
	Requests    float64 `json:"requests"`
	BytesIn     float64 `json:"bytes_in"`
	BytesOut    float64 `json:"bytes_out"`
}

// SystemMetrics holds system-level gauge values.
type SystemMetrics struct {
	UptimeSeconds    float64 `json:"uptime_seconds"`
	Goroutines       float64 `json:"goroutines"`
	MemoryAllocBytes float64 `json:"memory_alloc_bytes"`
	MemoryTotalBytes float64 `json:"memory_total_alloc_bytes"`
	MemorySysBytes   float64 `json:"memory_sys_bytes"`
	CPUUsage         float64 `json:"cpu_usage_percent"`
	MemoryUsage      float64 `json:"memory_usage_percent"`
	CPUCores         int     `json:"cpu_cores"`
	MemoryTotalGB    float64 `json:"memory_total_gb"`
	StorageUsageGB   float64 `json:"storage_usage_gb"`
	StorageTotalGB   float64 `json:"storage_total_gb"`
	StorageUsagePct  float64 `json:"storage_usage_percent"`
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
	return collectMetricsSnapshot(ctx, limit, offset)
}

func collectMetricsSnapshot(ctx context.Context, limit, offset int) (*MetricsSnapshot, error) {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return nil, err
	}

	idx := make(map[string]*dto.MetricFamily, len(families))
	for _, f := range families {
		idx[f.GetName()] = f
	}

	snap := &MetricsSnapshot{}
	snap.GoldenSignals = buildGoldenSignals(ctx, idx)
	snap.RouteMetrics = buildRouteMetrics(idx)
	snap.Middleware = buildMiddlewareMetrics(idx)
	snap.TLSCertificates = buildTLSCertMetrics(idx)
	snap.Targets = buildTargetMetrics(idx)
	snap.IPMetrics = buildIPMetrics(idx)
	snap.CountryMetrics = buildCountryMetrics(idx)
	snap.ProtocolMetrics = collectLabeledCounts(idx, "gateon_requests_by_protocol_total", "protocol")
	snap.DomainMetrics = buildDomainMetrics(idx)
	snap.HourlyDomainMetrics = GetDomainStatsWindow(ctx, 1)
	snap.DomainStatsRolling24h = GetDomainStatsRolling24h(ctx)
	snap.TrafficHistory = GetSystemTrafficHistory(ctx, dashboardTrendWindowDays())
	snap.System = buildSystemMetrics(idx)
	snap.Security = buildSecurityInsights(ctx, idx, limit, offset)
	if m := globalEbpfManager.Load(); m != nil {
		if ips, err := (*m).GetTopIPs(5); err == nil {
			snap.Security.EbpfTopIPs = ips
		}
	}
	snap.MitigationFunnel = buildMitigationFunnel(idx)

	// Build active threat metrics
	snap.ActiveSuspiciousSessions = gaugeValue(idx, "gateon_active_suspicious_sessions_total")
	snap.ActiveUnverifiedClients = gaugeValue(idx, "gateon_active_unverified_clients_total")
	snap.ActiveShunnedEntities = collectLabeledCounts(idx, "gateon_active_shunned_entities_total", "type")

	if fam, ok := idx["gateon_active_anomaly_score_average"]; ok {
		if m := fam.GetMetric(); len(m) > 0 {
			snap.ActiveAnomalyScoreAverage = m[0].GetGauge().GetValue()
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
		gs.ErrorRate = (gs.ErrorsTotal / gs.RequestsTotal) * 100
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
			gs.AvgLatencyMs = (totalSum / float64(totalCount)) * 1000
		}
		p := estimatePercentiles(fam, []float64{0.50, 0.95, 0.99}, match)
		gs.P50LatencyMs = p[0] * 1000
		gs.P95LatencyMs = p[1] * 1000
		gs.P99LatencyMs = p[2] * 1000
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

	f.TotalMitigated = f.WAFBlocked + f.RateLimited + f.GeoIPBlocked +
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
				rm.AvgLatency = (h.GetSampleSum() / float64(h.GetSampleCount())) * 1000
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
	mm.CacheHits = sumCounter(idx, "gateon_middleware_cache_hits_total", nil)
	mm.CacheMisses = sumCounter(idx, "gateon_middleware_cache_misses_total", nil)
	total := mm.CacheHits + mm.CacheMisses
	if total > 0 {
		mm.CacheHitRate = (mm.CacheHits / total) * 100
	}
	mm.AuthFailures = collectLabeledCounts(idx, "gateon_middleware_auth_failures_total", "auth_type")
	mm.CompressBytesIn = sumCounter(idx, "gateon_middleware_compress_bytes_in_total", nil)
	mm.CompressBytesOut = sumCounter(idx, "gateon_middleware_compress_bytes_out_total", nil)
	if mm.CompressBytesIn > 0 {
		mm.CompressionRatio = (1 - mm.CompressBytesOut/mm.CompressBytesIn) * 100
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

	return sm
}

func buildSecurityInsights(ctx context.Context, idx map[string]*dto.MetricFamily, limit, offset int) SecurityInsights {
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

	g.Go(func() error {
		threats = GetSecurityThreatsLite(ctx, limit, offset)
		return nil
	})
	g.Go(func() error {
		total = CountSecurityThreats(ctx)
		return nil
	})
	g.Go(func() error {
		activeCount = GetActiveThreatsRolling24h(ctx)
		return nil
	})
	g.Go(func() error {
		mitigated = GetMitigatedRolling24h(ctx)
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
		gs.ErrorRate = (gs.ErrorsTotal / gs.RequestsTotal) * 100
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
			gs.AvgLatencyMs = (totalSum / float64(totalCount)) * 1000
		}
		p := estimatePercentiles(fam, []float64{0.50, 0.95, 0.99}, isService)
		gs.P50LatencyMs = p[0] * 1000
		gs.P95LatencyMs = p[1] * 1000
		gs.P99LatencyMs = p[2] * 1000
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
