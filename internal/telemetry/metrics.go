package telemetry

import (
	"context"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
)

var (
	GlobalCMS = NewCMSketch(2048, 4)
	GlobalHHH = NewHHHCounter()
)

// StartEBpFPollLoop starts a background worker to poll eBPF stats and update Prometheus metrics.
func StartEBpFPollLoop(ctx context.Context, manager ebpf.Manager) {
	if manager == nil {
		return
	}

	// Poll cadence follows the resource profile: the minimal tier polls less
	// often to cut idle CPU wakeups, enterprise keeps the tight 2s cadence.
	interval := time.Duration(config.CurrentTierDefaults().EbpfPollSeconds) * time.Second
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logger.L.LogInfo("eBPF metrics polling loop started", "interval", interval)

	lastDropped := make(map[string]uint64)
	// Track attachment so we log the transition once (not every tick). attached
	// starts unset so the first observation is always logged — this is the
	// operator's answer to "why are the eBPF metrics zero?".
	var lastAttached *bool

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats, err := manager.GetMapStats()
			if err != nil {
				logger.L.LogError("failed to get eBPF map stats", "error", err)
				continue
			}

			if lastAttached == nil || *lastAttached != stats.Attached {
				if stats.Attached {
					logger.L.LogInfo("eBPF XDP program attached; metrics now live", "interface", stats.Interface, "mode", stats.AttachMode)
				} else {
					logger.L.LogError("eBPF enabled but XDP program is NOT attached; metrics will stay zero",
						"interface", stats.Interface, "load_error", stats.LoadError)
				}
				a := stats.Attached
				lastAttached = &a
			}

			ActiveShunnedEntitiesTotal.WithLabelValues("ip").Set(float64(stats.ShunnedIPsCount))

			for reason, count := range stats.DroppedPackets {
				if last, ok := lastDropped[reason]; ok {
					if count > last {
						EbpfDroppedPacketsTotal.WithLabelValues(reason).Add(float64(count - last))
					}
				} else if count > 0 {
					EbpfDroppedPacketsTotal.WithLabelValues(reason).Add(float64(count))
				}
				lastDropped[reason] = count
			}
		}
	}
}

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

// RequestFailuresTotal counts failed requests broken down by route and reason.
var RequestFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_request_failures_total",
	Help: "Total number of failed requests by route and reason.",
}, []string{"route", "reason"})

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

// MiddlewareBotManagementTotal counts bot management outcomes.
var MiddlewareBotManagementTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_middleware_bot_management_total",
	Help: "Total bot management challenge outcomes.",
}, []string{"route", "outcome"})

// ActiveThreatsTotal counts detected but not yet mitigated threats.
var ActiveThreatsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_active_threats_total",
	Help: "Total number of active (detected but not mitigated) threats.",
}, []string{"category", "severity"})

// MitigatedThreatsTotal counts mitigated threats by category and severity.
var MitigatedThreatsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_mitigated_threats_total",
	Help: "Total number of mitigated threats by category and severity.",
}, []string{"category", "severity", "action"})

// BotMitigationTotal counts bot mitigation by specific signal.
var BotMitigationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_bot_mitigation_total",
	Help: "Total bot mitigation events by signal.",
}, []string{"signal"})

// EbpfDroppedPacketsTotal counts packets dropped at the eBPF/XDP level.
var EbpfDroppedPacketsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_ebpf_dropped_packets_total",
	Help: "Total number of packets dropped by eBPF/XDP.",
}, []string{"reason"})

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

// perIPMetricsEnabled gates the per-client-IP Prometheus series above. It is
// disabled by default: the "ip" label is unbounded, so under many distinct
// clients (worst during a DDoS, exactly when the gateway must survive) these
// CounterVecs grow without bound and leak memory. The bounded GetAggregator,
// Count-Min Sketch, and heavy-hitter structures already provide per-IP
// analytics for the dashboard. Opt in with GATEON_PER_IP_METRICS=1 (or =true)
// for short-lived debugging on a trusted, low-cardinality network.
var perIPMetricsEnabled = func() bool {
	switch os.Getenv("GATEON_PER_IP_METRICS") {
	case "1", "true", "TRUE", "True":
		return true
	default:
		return false
	}
}()

// PerIPMetricsEnabled reports whether per-client-IP Prometheus metrics are exported.
func PerIPMetricsEnabled() bool { return perIPMetricsEnabled }

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

// --- Gauges ---

// ActiveSuspiciousSessionsTotal tracks the number of active suspicious client sessions.
var ActiveSuspiciousSessionsTotal = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "gateon_active_suspicious_sessions_total",
	Help: "Number of active client sessions with a low reputation score.",
})

// ActiveShunnedEntitiesTotal tracks the number of entities currently in the eBPF/XDP blocklists.
var ActiveShunnedEntitiesTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "gateon_active_shunned_entities_total",
	Help: "Total number of entries currently in the eBPF/XDP blocklists.",
}, []string{"type"})

// ActiveAnomalyScore tracks current anomaly scores across all active clients.
var ActiveAnomalyScore = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "gateon_active_anomaly_score",
	Help:    "Histogram of current anomaly scores across all active clients.",
	Buckets: []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
})

// ActiveUnverifiedClientsTotal tracks the number of clients currently in a challenge state.
var ActiveUnverifiedClientsTotal = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "gateon_active_unverified_clients_total",
	Help: "Number of clients currently in the JS Challenge or Captcha state.",
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

	// System metrics gauges (global so they can be accessed by GetSystemStats)
	goroutinesGauge  prometheus.Gauge
	memoryAllocGauge prometheus.Gauge
	memoryTotalGauge prometheus.Gauge
	memorySysGauge   prometheus.Gauge
	cpuUsageGauge    prometheus.Gauge
	memoryUsageGauge prometheus.Gauge

	// Latest values for API
	lastCPUUsage    atomic.Pointer[float64]
	lastMemoryUsage atomic.Pointer[float64]
)

// InitStartTime records the gateway start time for uptime tracking.
func InitStartTime() {
	startTimeOnce.Do(func() {
		startTime = time.Now()
	})
}

// GetStartTime returns the gateway start time.
func GetStartTime() time.Time {
	return startTime
}

// SystemStats holds current system-level metrics.
type SystemStats struct {
	CPUUsage           float64
	MemoryUsagePercent float64
}

// GetSystemStats returns the current system metrics.
func GetSystemStats() SystemStats {
	var stats SystemStats
	if v := lastCPUUsage.Load(); v != nil {
		stats.CPUUsage = *v
	}
	if v := lastMemoryUsage.Load(); v != nil {
		stats.MemoryUsagePercent = *v
	}
	return stats
}

// StartSystemMetricsCollector starts a background goroutine that periodically updates
// system-level gauges (uptime, goroutines, memory). It stops when ctx is cancelled.
func StartSystemMetricsCollector(stop <-chan struct{}) {
	goroutinesGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_goroutines",
		Help: "Current number of goroutines.",
	})
	memoryAllocGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_memory_alloc_bytes",
		Help: "Current heap allocation in bytes.",
	})
	memoryTotalGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_memory_total_alloc_bytes",
		Help: "Total heap allocations over lifetime in bytes.",
	})
	memorySysGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_memory_sys_bytes",
		Help: "Total memory obtained from the OS in bytes.",
	})
	cpuUsageGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_cpu_usage_percent",
		Help: "Current system CPU usage percentage.",
	})
	memoryUsageGauge = promauto.NewGauge(prometheus.GaugeOpts{
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
				goroutinesGauge.Set(float64(runtime.NumGoroutine()))
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				memoryAllocGauge.Set(float64(m.Alloc))
				memoryTotalGauge.Set(float64(m.TotalAlloc))
				memorySysGauge.Set(float64(m.Sys))

				// System-wide metrics
				if v, err := mem.VirtualMemory(); err == nil {
					memoryUsageGauge.Set(v.UsedPercent)
					lastMemoryUsage.Store(new(v.UsedPercent))
				}
				if c, err := cpu.Percent(0, false); err == nil && len(c) > 0 {
					cpuUsageGauge.Set(c[0])
					lastCPUUsage.Store(new(c[0]))
				}

				// Process-specific metrics
				if proc != nil {
					if n, err := proc.NumFDs(); err == nil {
						OpenFileDescriptors.Set(float64(n))
					}
				}

				// SQLite WAL metrics - optimized to check only specific files
				for _, dbFile := range []string{"gateon.db"} {
					walPath := dbFile + "-wal"
					if info, err := os.Stat(walPath); err == nil && !info.IsDir() {
						SQLiteWALSize.WithLabelValues(dbFile).Set(float64(info.Size()))
					}
				}

				// Reputation metrics
				UpdateReputationMetrics()
			case <-stop:
				return
			}
		}
	}()
}
