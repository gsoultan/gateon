package telemetry

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
)

// --- Counters ---

// RequestsTotal counts HTTP requests broken down by route, service, method, and status code.
var RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_requests_total",
	Help: "Total number of HTTP requests by route, service, method, and status code.",
}, []string{"route", "service", "method", "status_code"})

// RequestBytesTotal counts request/response bytes by route and direction.
var RequestBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_request_bytes_total",
	Help: "Total bytes transferred by route and direction (in/out).",
}, []string{"route", "direction"})

// MiddlewareRateLimitRejectedTotal counts requests rejected by rate limiter.
var MiddlewareRateLimitRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_middleware_ratelimit_rejected_total",
	Help: "Total requests rejected by rate limiter.",
}, []string{"route", "limiter_type"})

// MiddlewareRateLimitRemainingQuota tracks remaining rate limit quota.
var MiddlewareRateLimitRemainingQuota = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "gateon_middleware_ratelimit_remaining_quota",
	Help: "Remaining rate limit quota.",
}, []string{"route"})

// MiddlewareWAFBlockedTotal counts requests blocked by WAF.
var MiddlewareWAFBlockedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_middleware_waf_blocked_total",
	Help: "Total requests blocked by WAF.",
}, []string{"route", "rule_id"})

// MiddlewareCacheHitsTotal counts cache hits.
var MiddlewareCacheHitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_middleware_cache_hits_total",
	Help: "Total cache hits.",
}, []string{"route"})

// MiddlewareCacheMissesTotal counts cache misses.
var MiddlewareCacheMissesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_middleware_cache_misses_total",
	Help: "Total cache misses.",
}, []string{"route"})

// MiddlewareCacheEvictionTotal counts cache evictions.
var MiddlewareCacheEvictionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_middleware_cache_eviction_total",
	Help: "Total cache evictions.",
}, []string{"route"})

// MiddlewareAuthFailuresTotal counts authentication/authorization failures.
var MiddlewareAuthFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_middleware_auth_failures_total",
	Help: "Total authentication/authorization failures.",
}, []string{"route", "auth_type"})

// CircuitBreakerStateChangesTotal counts circuit breaker state transitions.
var CircuitBreakerStateChangesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_circuit_breaker_state_changes_total",
	Help: "Total circuit breaker state transitions.",
}, []string{"route", "target", "from_state", "to_state"})

// RetriesTotal counts retry attempts per route.
var RetriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_retries_total",
	Help: "Total retry attempts.",
}, []string{"route", "outcome"})

// TLSACMERenewalsTotal counts ACME certificate renewal attempts.
var TLSACMERenewalsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_tls_acme_renewals_total",
	Help: "Total ACME certificate renewal attempts.",
}, []string{"domain", "outcome"})

// MiddlewareCompressBytesTotalIn counts pre-compression bytes.
var MiddlewareCompressBytesTotalIn = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_middleware_compress_bytes_in_total",
	Help: "Total bytes before compression.",
}, []string{"route"})

// MiddlewareCompressBytesTotalOut counts post-compression bytes.
var MiddlewareCompressBytesTotalOut = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_middleware_compress_bytes_out_total",
	Help: "Total bytes after compression.",
}, []string{"route"})

// MiddlewareTurnstileTotal counts Turnstile verification outcomes.
var MiddlewareTurnstileTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_middleware_turnstile_total",
	Help: "Total Turnstile challenge outcomes.",
}, []string{"route", "outcome"})

// MiddlewareGeoIPBlockedTotal counts GeoIP blocks by country.
var MiddlewareGeoIPBlockedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_middleware_geoip_blocked_total",
	Help: "Total requests blocked by GeoIP.",
}, []string{"route", "country"})

// MiddlewareHMACFailuresTotal counts HMAC verification failures.
var MiddlewareHMACFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_middleware_hmac_failures_total",
	Help: "Total HMAC verification failures.",
}, []string{"route"})

// RequestsByIPTotal counts HTTP requests by client IP.
var RequestsByIPTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_requests_by_ip_total",
	Help: "Total number of HTTP requests by client IP.",
}, []string{"ip"})

// RequestBytesByIPTotal counts request/response bytes by client IP and direction.
var RequestBytesByIPTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_request_bytes_by_ip_total",
	Help: "Total bytes transferred by client IP and direction (in/out).",
}, []string{"ip", "direction"})

// RequestsByCountryTotal counts HTTP requests by country.
var RequestsByCountryTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_requests_by_country_total",
	Help: "Total number of HTTP requests by country.",
}, []string{"country"})

// RequestBytesByCountryTotal counts request/response bytes by country and direction.
var RequestBytesByCountryTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_request_bytes_by_country_total",
	Help: "Total bytes transferred by country and direction (in/out).",
}, []string{"country", "direction"})

// RequestsByDomainTotal counts HTTP requests by domain.
var RequestsByDomainTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_requests_by_domain_total",
	Help: "Total number of HTTP requests by domain.",
}, []string{"domain"})

// RequestBytesByDomainTotal counts request/response bytes by domain and direction.
var RequestBytesByDomainTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_request_bytes_by_domain_total",
	Help: "Total bytes transferred by domain and direction (in/out).",
}, []string{"domain", "direction"})

// RequestsByProtocolTotal counts HTTP requests by protocol (http1, http2, http3).
var RequestsByProtocolTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_requests_by_protocol_total",
	Help: "Total number of HTTP requests by protocol.",
}, []string{"protocol"})

// ConfigReloadsTotal counts configuration reloads.
var ConfigReloadsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gateon_config_reloads_total",
	Help: "Total number of configuration reloads.",
})

// ProxyCacheInvalidationsTotal counts proxy cache invalidation events.
var ProxyCacheInvalidationsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gateon_proxy_cache_invalidations_total",
	Help: "Total proxy cache invalidation events.",
})

// --- Histograms ---

// RequestDurationSeconds observes request duration as a histogram with SLA-friendly buckets.
var RequestDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "gateon_request_duration_seconds",
	Help:    "Histogram of request duration in seconds.",
	Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
}, []string{"route", "service", "method"})

// UpstreamConnectDurationSeconds observes upstream TCP connect duration.
var UpstreamConnectDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "gateon_upstream_connect_duration_seconds",
	Help:    "Histogram of upstream connect duration in seconds.",
	Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
}, []string{"route", "target"})

// TLSHandshakeDurationSeconds observes TLS handshake duration.
var TLSHandshakeDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "gateon_tls_handshake_duration_seconds",
	Help:    "Histogram of TLS handshake duration in seconds.",
	Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
}, []string{"entrypoint"})

// TTFBSeconds observes time-to-first-byte as a histogram.
var TTFBSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "gateon_ttfb_seconds",
	Help:    "Histogram of time-to-first-byte in seconds.",
	Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
}, []string{"route"})

// --- Gauges ---

// RequestsInFlight tracks currently in-flight requests per route.
var RequestsInFlight = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "gateon_requests_in_flight",
	Help: "Number of currently in-flight requests.",
}, []string{"route"})

// ActiveConnections tracks active connections per target.
var ActiveConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "gateon_active_connections",
	Help: "Number of active connections per target.",
}, []string{"target"})

// TargetHealth tracks target health (1=healthy, 0=unhealthy).
var TargetHealth = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "gateon_target_health",
	Help: "Health status of a target (1=healthy, 0=unhealthy).",
}, []string{"route", "target"})

// TLSCertificateExpirySeconds tracks TLS certificate expiry time in seconds since epoch.
var TLSCertificateExpirySeconds = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "gateon_tls_certificate_expiry_seconds",
	Help: "Expiry time of TLS certificate in seconds since Unix epoch.",
}, []string{"domain", "cert_name"})

// ConfigReloadTimestamp tracks the last configuration reload timestamp.
var ConfigReloadTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "gateon_config_reload_timestamp_seconds",
	Help: "Unix timestamp of the last configuration reload.",
})

// UptimeSeconds tracks gateway uptime in seconds.
var UptimeSeconds = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "gateon_uptime_seconds",
	Help: "Gateway uptime in seconds.",
})

// OpenFileDescriptors tracks current open file descriptors.
var OpenFileDescriptors = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "gateon_open_file_descriptors",
	Help: "Current number of open file descriptors.",
})

// SQLiteWALSize tracks the size of the SQLite WAL file.
var SQLiteWALSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "gateon_sqlite_wal_size",
	Help: "Current size of the SQLite WAL file in bytes.",
}, []string{"database"})

var (
	startTime     time.Time
	startTimeOnce sync.Once
)

// InitStartTime records the gateway start time for uptime tracking.
func InitStartTime() {
	startTimeOnce.Do(func() {
		startTime = time.Now()
	})
}

// StartSystemMetricsCollector starts a background goroutine that periodically updates
// system-level gauges (uptime, goroutines, memory). It stops when ctx is cancelled.
func StartSystemMetricsCollector(stop <-chan struct{}) {
	goroutines := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_goroutines",
		Help: "Current number of goroutines.",
	})
	memoryAlloc := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_memory_alloc_bytes",
		Help: "Current heap allocation in bytes.",
	})
	memoryTotalAlloc := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_memory_total_alloc_bytes",
		Help: "Total heap allocations over lifetime in bytes.",
	})
	memorySys := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_memory_sys_bytes",
		Help: "Total memory obtained from the OS in bytes.",
	})
	cpuUsage := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_cpu_usage_percent",
		Help: "Current system CPU usage percentage.",
	})
	memoryUsage := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_memory_usage_percent",
		Help: "Current system memory usage percentage.",
	})

	proc, _ := process.NewProcess(int32(os.Getpid()))

	ticker := time.NewTicker(10 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if !startTime.IsZero() {
					UptimeSeconds.Set(time.Since(startTime).Seconds())
				}
				goroutines.Set(float64(runtime.NumGoroutine()))
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				memoryAlloc.Set(float64(m.Alloc))
				memoryTotalAlloc.Set(float64(m.TotalAlloc))
				memorySys.Set(float64(m.Sys))

				// System-wide metrics
				if v, err := mem.VirtualMemory(); err == nil {
					memoryUsage.Set(v.UsedPercent)
				}
				if c, err := cpu.Percent(0, false); err == nil && len(c) > 0 {
					cpuUsage.Set(c[0])
				}

				// Process-specific metrics
				if proc != nil {
					if n, err := proc.NumFDs(); err == nil {
						OpenFileDescriptors.Set(float64(n))
					}
				}

				// SQLite WAL metrics
				_ = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
					if err == nil && !info.IsDir() && filepath.Ext(path) == ".db-wal" {
						SQLiteWALSize.WithLabelValues(filepath.Base(path)).Set(float64(info.Size()))
					}
					return nil
				})
			case <-stop:
				return
			}
		}
	}()
}
