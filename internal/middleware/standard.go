package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"
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
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &StatusResponseWriter{ResponseWriter: w, Status: http.StatusOK}

			next.ServeHTTP(sw, r)

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
		})
	}
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
