package middleware

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
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

			status := "success"
			if sw.Status >= 400 {
				status = "error"
			}
			telemetry.RecordTrace(
				request.GetID(r),
				r.Method+" "+r.URL.Path,
				routeID,
				duration.Milliseconds(),
				start,
				status,
				r.Host+r.URL.Path,
			)

			httpRequestsTotal.WithLabelValues(routeID, r.Method, getStatusString(sw.Status)).Inc()
			httpDuration.WithLabelValues(routeID, r.Method).Observe(duration.Seconds())
		})
	}
}

// parsedIPRule holds a pre-parsed IP filter rule (exact IP or CIDR) to avoid per-request parsing.
type parsedIPRule struct {
	exact string     // non-empty for exact match
	cidr  *net.IPNet // non-nil for CIDR match
}

func parseIPRules(rules []string) []parsedIPRule {
	parsed := make([]parsedIPRule, len(rules))
	for i, r := range rules {
		if _, ipnet, err := net.ParseCIDR(r); err == nil {
			parsed[i] = parsedIPRule{cidr: ipnet}
		} else {
			parsed[i] = parsedIPRule{exact: r}
		}
	}
	return parsed
}

func matchParsedIP(clientIP string, rule parsedIPRule) bool {
	if rule.exact != "" {
		return clientIP == rule.exact
	}
	if rule.cidr != nil {
		ip := net.ParseIP(clientIP)
		return ip != nil && rule.cidr.Contains(ip)
	}
	return false
}

// IPFilterWithClientIP returns a middleware that filters requests by IP address using the given clientIP resolver.
// CIDRs are pre-parsed at construction time to avoid per-request overhead.
func IPFilterWithClientIP(allowList, denyList []string, clientIP func(*http.Request) string) Middleware {
	parsedDeny := parseIPRules(denyList)
	parsedAllow := parseIPRules(allowList)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteAddr := clientIP(r)

			// Deny list takes precedence
			for _, rule := range parsedDeny {
				if matchParsedIP(remoteAddr, rule) {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}

			if len(parsedAllow) > 0 {
				found := false
				for _, rule := range parsedAllow {
					if matchParsedIP(remoteAddr, rule) {
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

// IPFilter returns a middleware that filters requests by IP address, using X-Forwarded-For and RemoteAddr.
// For Cloudflare, use IPFilterWithClientIP with a resolver that uses CF-Connecting-IP.
func IPFilter(allowList, denyList []string) Middleware {
	return IPFilterWithClientIP(allowList, denyList, func(r *http.Request) string {
		return request.GetClientIP(r, request.TrustCloudflareFromEnv())
	})
}

// HostFilter returns a middleware that filters requests by Host header.
// If host is empty, it allows all hosts.
func HostFilter(host string) Middleware {
	if host == "" {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Strip port if present for comparison
			h := r.Host
			if sh, _, err := net.SplitHostPort(h); err == nil {
				h = sh
			}

			if !strings.EqualFold(h, host) {
				http.Error(w, "Forbidden: Invalid Host", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func lastIndex(s, sep string) int {
	return strings.LastIndex(s, sep)
}

// RequestID returns a middleware that adds a unique ID to each request.
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-ID")
			if id == "" {
				id = request.GenerateID()
			}
			w.Header().Set("X-Request-ID", id)
			r = r.WithContext(request.WithID(r.Context(), id))
			next.ServeHTTP(w, r)
		})
	}
}
