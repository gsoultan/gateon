package middleware

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gateon/gateon/internal/logger"
	"github.com/gateon/gateon/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var statusCodes = make(map[int]string)

func init() {
	for i := 100; i < 600; i++ {
		statusCodes[i] = strconv.Itoa(i)
	}
}

func getStatusString(code int) string {
	if s, ok := statusCodes[code]; ok {
		return s
	}
	return strconv.Itoa(code)
}

var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateon_http_requests_total",
		Help: "Total number of HTTP requests",
	}, []string{"route_id", "method", "status"})

	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "gateon_http_duration_seconds",
		Help:    "Latency of HTTP requests",
		Buckets: prometheus.DefBuckets,
	}, []string{"route_id", "method"})
)

// StatusResponseWriter wraps http.ResponseWriter to capture status code.
type StatusResponseWriter struct {
	http.ResponseWriter
	Status int
}

func (w *StatusResponseWriter) WriteHeader(code int) {
	w.Status = code
	w.ResponseWriter.WriteHeader(code)
}

// AccessLog returns a middleware that logs request details.
func AccessLog(routeID string) Middleware {
	return AccessLogSampled(routeID, accessLogSampleRate())
}

// AccessLogSampled returns a middleware that logs a sample of requests.
// When sampleRate is 0, no requests are logged. When 1, all requests are logged.
// When >1, logs approximately 1 in sampleRate requests (for high-throughput, use 1000+).
func AccessLogSampled(routeID string, sampleRate uint32) Middleware {
	if sampleRate == 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	var counter uint64
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &StatusResponseWriter{ResponseWriter: w, Status: http.StatusOK}

			next.ServeHTTP(sw, r)

			if sampleRate == 1 || (atomic.AddUint64(&counter, 1)%uint64(sampleRate) == 0) {
				duration := time.Since(start)
				logger.L.Info().
					Str("host", r.Host).
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Str("remote_addr", r.RemoteAddr).
					Int("status", sw.Status).
					Dur("latency", duration).
					Str("route_id", routeID).
					Msg("access log")
			}
		})
	}
}

// accessLogSampleRate returns GATEON_ACCESS_LOG_SAMPLE_RATE (1=all, 0=none, N=1-in-N). Default 1.
func accessLogSampleRate() uint32 {
	s := os.Getenv("GATEON_ACCESS_LOG_SAMPLE_RATE")
	if s == "" {
		return 1
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return 0 // invalid or 0 => no access log
	}
	return uint32(n)
}

// Metrics returns a middleware that records prometheus metrics.
func Metrics(routeID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw, ok := w.(*StatusResponseWriter)
			if !ok {
				sw = &StatusResponseWriter{ResponseWriter: w, Status: http.StatusOK}
				w = sw
			}

			next.ServeHTTP(sw, r)

			duration := time.Since(start)
			telemetry.RecordPathRequest(r.Host, r.URL.Path, duration.Seconds())
			httpRequestsTotal.WithLabelValues(routeID, r.Method, getStatusString(sw.Status)).Inc()
			httpDuration.WithLabelValues(routeID, r.Method).Observe(duration.Seconds())
		})
	}
}

// IPFilter returns a middleware that filters requests by IP address.
func IPFilter(allowList, denyList []string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				remoteAddr = r.RemoteAddr
			}

			// Deny list takes precedence
			for _, ip := range denyList {
				if matchIP(remoteAddr, ip) {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}

			if len(allowList) > 0 {
				found := false
				for _, ip := range allowList {
					if matchIP(remoteAddr, ip) {
						found = true
						break
					}
				}
				if !found {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func matchIP(clientIP, target string) bool {
	if clientIP == target {
		return true
	}
	// Check CIDR
	if _, ipnet, err := net.ParseCIDR(target); err == nil {
		ip := net.ParseIP(clientIP)
		if ip == nil {
			return false
		}
		return ipnet.Contains(ip)
	}
	return false
}

func lastIndex(s, sep string) int {
	return strings.LastIndex(s, sep)
}
