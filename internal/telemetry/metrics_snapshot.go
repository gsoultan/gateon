package telemetry

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// MetricsSnapshot holds a structured view of all Prometheus metrics for the UI.
type MetricsSnapshot struct {
	// Golden signals
	GoldenSignals GoldenSignals `json:"golden_signals"`

	// Per-route request metrics broken down by status code.
	RouteMetrics []RouteMetric `json:"route_metrics"`

	// Middleware counters (rate limit, WAF, cache, auth, compress, turnstile, geoip, hmac).
	Middleware MiddlewareMetrics `json:"middleware"`

	// TLS certificate expiry information.
	TLSCertificates []TLSCertMetric `json:"tls_certificates"`

	// Target health and connection status.
	Targets []TargetMetric `json:"targets"`

	// System-level gauges.
	System SystemMetrics `json:"system"`
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
	StatusCodes map[string]float64 `json:"status_codes"`
}

// MiddlewareMetrics holds counters for all middleware instrumentation.
type MiddlewareMetrics struct {
	RateLimitRejected  []LabeledCount `json:"rate_limit_rejected"`
	WAFBlocked         []LabeledCount `json:"waf_blocked"`
	CacheHits          float64        `json:"cache_hits"`
	CacheMisses        float64        `json:"cache_misses"`
	CacheHitRate       float64        `json:"cache_hit_rate"`
	AuthFailures       []LabeledCount `json:"auth_failures"`
	CompressBytesIn    float64        `json:"compress_bytes_in"`
	CompressBytesOut   float64        `json:"compress_bytes_out"`
	CompressionRatio   float64        `json:"compression_ratio"`
	TurnstilePass      float64        `json:"turnstile_pass"`
	TurnstileFail      float64        `json:"turnstile_fail"`
	GeoIPBlocked       []LabeledCount `json:"geoip_blocked"`
	HMACFailures       float64        `json:"hmac_failures"`
	RetriesSuccess     float64        `json:"retries_success"`
	RetriesFailure     float64        `json:"retries_failure"`
	ConfigReloads      float64        `json:"config_reloads"`
	CacheInvalidations float64        `json:"cache_invalidations"`
}

// LabeledCount is a metric value with a descriptive label.
type LabeledCount struct {
	Label string  `json:"label"`
	Value float64 `json:"value"`
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

// SystemMetrics holds system-level gauge values.
type SystemMetrics struct {
	UptimeSeconds    float64 `json:"uptime_seconds"`
	Goroutines       float64 `json:"goroutines"`
	MemoryAllocBytes float64 `json:"memory_alloc_bytes"`
	MemoryTotalBytes float64 `json:"memory_total_alloc_bytes"`
	MemorySysBytes   float64 `json:"memory_sys_bytes"`
}

// CollectMetricsSnapshot gathers all registered Prometheus metrics into a structured snapshot.
func CollectMetricsSnapshot() (*MetricsSnapshot, error) {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return nil, err
	}

	idx := make(map[string]*dto.MetricFamily, len(families))
	for _, f := range families {
		idx[f.GetName()] = f
	}

	snap := &MetricsSnapshot{}
	snap.GoldenSignals = buildGoldenSignals(idx)
	snap.RouteMetrics = buildRouteMetrics(idx)
	snap.Middleware = buildMiddlewareMetrics(idx)
	snap.TLSCertificates = buildTLSCertMetrics(idx)
	snap.Targets = buildTargetMetrics(idx)
	snap.System = buildSystemMetrics(idx)

	return snap, nil
}

func buildGoldenSignals(idx map[string]*dto.MetricFamily) GoldenSignals {
	gs := GoldenSignals{}

	gs.RequestsTotal = sumCounter(idx, "gateon_requests_total", nil)

	// Errors = 5xx status codes
	if fam, ok := idx["gateon_requests_total"]; ok {
		for _, m := range fam.GetMetric() {
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
			h := m.GetHistogram()
			totalSum += h.GetSampleSum()
			totalCount += h.GetSampleCount()
		}
		if totalCount > 0 {
			gs.AvgLatencyMs = (totalSum / float64(totalCount)) * 1000
		}
		gs.P50LatencyMs = estimatePercentile(fam, 0.50) * 1000
		gs.P95LatencyMs = estimatePercentile(fam, 0.95) * 1000
		gs.P99LatencyMs = estimatePercentile(fam, 0.99) * 1000
	}

	gs.InFlightTotal = sumGauge(idx, "gateon_requests_in_flight")
	gs.ActiveConnTotal = sumGauge(idx, "gateon_active_connections")

	if fam, ok := idx["gateon_request_bytes_total"]; ok {
		for _, m := range fam.GetMetric() {
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

func buildRouteMetrics(idx map[string]*dto.MetricFamily) []RouteMetric {
	routeMap := make(map[string]*RouteMetric)

	if fam, ok := idx["gateon_requests_total"]; ok {
		for _, m := range fam.GetMetric() {
			route := labelValue(m, "route")
			if route == "" {
				continue
			}
			rm := getOrCreateRoute(routeMap, route)
			if svc := labelValue(m, "service"); svc != "" {
				rm.Service = svc
			}
			sc := labelValue(m, "status_code")
			val := m.GetCounter().GetValue()
			rm.Requests += val
			rm.StatusCodes[sc] = rm.StatusCodes[sc] + val
			if strings.HasPrefix(sc, "5") {
				rm.Errors += val
			}
		}
	}

	if fam, ok := idx["gateon_requests_in_flight"]; ok {
		for _, m := range fam.GetMetric() {
			route := labelValue(m, "route")
			if route == "" {
				continue
			}
			rm := getOrCreateRoute(routeMap, route)
			rm.InFlight = m.GetGauge().GetValue()
		}
	}

	if fam, ok := idx["gateon_request_bytes_total"]; ok {
		for _, m := range fam.GetMetric() {
			route := labelValue(m, "route")
			if route == "" {
				continue
			}
			rm := getOrCreateRoute(routeMap, route)
			dir := labelValue(m, "direction")
			switch dir {
			case "in":
				rm.BytesIn += m.GetCounter().GetValue()
			case "out":
				rm.BytesOut += m.GetCounter().GetValue()
			}
		}
	}

	if fam, ok := idx["gateon_request_duration_seconds"]; ok {
		for _, m := range fam.GetMetric() {
			route := labelValue(m, "route")
			if route == "" {
				continue
			}
			rm := getOrCreateRoute(routeMap, route)
			h := m.GetHistogram()
			if h.GetSampleCount() > 0 {
				rm.AvgLatency = (h.GetSampleSum() / float64(h.GetSampleCount())) * 1000
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
			for key, tm := range targMap {
				if strings.Contains(key, target) {
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

func buildSystemMetrics(idx map[string]*dto.MetricFamily) SystemMetrics {
	return SystemMetrics{
		UptimeSeconds:    gaugeValue(idx, "gateon_uptime_seconds"),
		Goroutines:       gaugeValue(idx, "gateon_goroutines"),
		MemoryAllocBytes: gaugeValue(idx, "gateon_memory_alloc_bytes"),
		MemoryTotalBytes: gaugeValue(idx, "gateon_memory_total_alloc_bytes"),
		MemorySysBytes:   gaugeValue(idx, "gateon_memory_sys_bytes"),
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

func sumGauge(idx map[string]*dto.MetricFamily, name string) float64 {
	fam, ok := idx[name]
	if !ok {
		return 0
	}
	var total float64
	for _, m := range fam.GetMetric() {
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
		agg[lbl] += m.GetCounter().GetValue()
	}
	result := make([]LabeledCount, 0, len(agg))
	for label, val := range agg {
		if val > 0 {
			result = append(result, LabeledCount{Label: label, Value: val})
		}
	}
	return result
}

// estimatePercentile estimates a percentile from a histogram using linear interpolation.
func estimatePercentile(fam *dto.MetricFamily, q float64) float64 {
	var totalCount uint64
	for _, m := range fam.GetMetric() {
		totalCount += m.GetHistogram().GetSampleCount()
	}
	if totalCount == 0 {
		return 0
	}

	// Merge all buckets across label combinations.
	type bucket struct {
		upperBound      float64
		cumulativeCount uint64
	}
	bucketMap := make(map[float64]uint64)
	for _, m := range fam.GetMetric() {
		for _, b := range m.GetHistogram().GetBucket() {
			bucketMap[b.GetUpperBound()] += b.GetCumulativeCount()
		}
	}

	buckets := make([]bucket, 0, len(bucketMap))
	for ub, cc := range bucketMap {
		buckets = append(buckets, bucket{upperBound: ub, cumulativeCount: cc})
	}

	// Sort by upper bound.
	for i := range len(buckets) {
		for j := i + 1; j < len(buckets); j++ {
			if buckets[j].upperBound < buckets[i].upperBound {
				buckets[i], buckets[j] = buckets[j], buckets[i]
			}
		}
	}

	target := q * float64(totalCount)
	var prevBound float64
	var prevCount uint64
	for _, b := range buckets {
		if float64(b.cumulativeCount) >= target {
			// Linear interpolation within this bucket.
			countInBucket := float64(b.cumulativeCount - prevCount)
			if countInBucket <= 0 {
				return b.upperBound
			}
			fraction := (target - float64(prevCount)) / countInBucket
			return prevBound + fraction*(b.upperBound-prevBound)
		}
		prevBound = b.upperBound
		prevCount = b.cumulativeCount
	}

	// Fallback: return the highest bucket bound.
	if len(buckets) > 0 {
		return buckets[len(buckets)-1].upperBound
	}
	return 0
}
