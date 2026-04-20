package middleware

import (
	"cmp"
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

// StatusResponseWriter wraps http.ResponseWriter to capture status code, bytes written, and TTFB.
type StatusResponseWriter struct {
	http.ResponseWriter
	Status       int
	BytesWritten int64
	ttfbRecorded bool
	firstByte    time.Time
	start        time.Time
}

func (w *StatusResponseWriter) WriteHeader(code int) {
	if !w.ttfbRecorded {
		w.firstByte = time.Now()
		w.ttfbRecorded = true
	}
	w.Status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *StatusResponseWriter) Write(b []byte) (int, error) {
	if !w.ttfbRecorded {
		w.firstByte = time.Now()
		w.ttfbRecorded = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.BytesWritten += int64(n)
	return n, err
}

// TTFB returns the time-to-first-byte duration. Returns zero if no bytes were written.
func (w *StatusResponseWriter) TTFB() time.Duration {
	if !w.ttfbRecorded {
		return 0
	}
	return w.firstByte.Sub(w.start)
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

			// Capture original values before proxying mutates the request.
			origHost := r.Host
			origMethod := r.Method
			origPath := r.URL.Path
			remoteAddr := r.RemoteAddr

			sw := &StatusResponseWriter{ResponseWriter: w, Status: http.StatusOK, start: start}

			next.ServeHTTP(sw, r)

			if sampleRate == 1 || (atomic.AddUint64(&counter, 1)%uint64(sampleRate) == 0) {
				duration := time.Since(start)
				logger.L.Info().
					Str("host", origHost).
					Str("method", origMethod).
					Str("path", origPath).
					Str("remote_addr", remoteAddr).
					Int("status", sw.Status).
					Dur("latency", duration).
					Str("route", routeID).
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

// Metrics returns a middleware that records comprehensive Prometheus metrics
// including request counts, latency histograms, status code breakdown,
// body size tracking, TTFB, and in-flight request gauges.
func Metrics(routeID string) Middleware {
	return MetricsWithService(routeID, "")
}

// MetricsWithService returns a metrics middleware that also records the service label.
func MetricsWithService(routeID, serviceID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ShouldSkipMetrics(r) {
				next.ServeHTTP(w, r)
				return
			}
			// Use explicit routeID if provided, otherwise fallback to context.
			activeRouteID := routeID
			if activeRouteID == "" {
				activeRouteID = GetRouteName(r)
			}

			start := time.Now()

			// Track in-flight requests
			telemetry.RequestsInFlight.WithLabelValues(activeRouteID).Inc()
			defer telemetry.RequestsInFlight.WithLabelValues(activeRouteID).Dec()

			// Capture original host and path before proxying mutates r.Host/r.URL.
			origHost := cmp.Or(r.Host, r.URL.Host)
			origPath := r.URL.Path
			method := r.Method

			// Track request body size
			reqInSize := r.ContentLength
			if reqInSize < 0 {
				reqInSize = 0
			}
			// Add a baseline of 256 bytes to account for headers and request line.
			telemetry.RequestBytesTotal.WithLabelValues(activeRouteID, "in").Add(float64(reqInSize + 256))

			sw, ok := w.(*StatusResponseWriter)
			if !ok {
				sw = &StatusResponseWriter{ResponseWriter: w, Status: http.StatusOK, start: start}
				w = sw
			}

			next.ServeHTTP(sw, r)

			respOutSize := sw.BytesWritten
			if respOutSize < 0 {
				respOutSize = 0
			}
			totalBandwidthBytes := uint64(reqInSize+256) + uint64(respOutSize+200)

			duration := time.Since(start)
			telemetry.RecordPathRequest(origHost, origPath, duration.Seconds(), totalBandwidthBytes)

			status := "success"
			if sw.Status >= 400 {
				status = "error"
			}
			telemetry.RecordTrace(
				request.GetID(r),
				method+" "+origPath,
				activeRouteID,
				float64(duration.Nanoseconds())/1e6,
				start,
				status,
				origHost+origPath,
			)

			statusStr := getStatusString(sw.Status)

			// Rich Prometheus metrics
			telemetry.RequestsTotal.WithLabelValues(activeRouteID, serviceID, method, statusStr).Inc()
			telemetry.RequestDurationSeconds.WithLabelValues(activeRouteID, serviceID, method).Observe(duration.Seconds())

			// IP-based metrics
			clientIP := request.GetClientIP(r, request.TrustCloudflareFromEnv())
			telemetry.RequestsByIPTotal.WithLabelValues(clientIP).Inc()
			telemetry.RequestBytesByIPTotal.WithLabelValues(clientIP, "in").Add(float64(reqInSize + 256))
			telemetry.RequestBytesByIPTotal.WithLabelValues(clientIP, "out").Add(float64(respOutSize + 200))

			// Country-based metrics
			country := request.GetCountry(r)
			telemetry.RequestsByCountryTotal.WithLabelValues(country).Inc()
			telemetry.RequestBytesByCountryTotal.WithLabelValues(country, "in").Add(float64(reqInSize + 256))
			telemetry.RequestBytesByCountryTotal.WithLabelValues(country, "out").Add(float64(respOutSize + 200))

			// Domain-based metrics
			origDomain := origHost
			if h, _, err := net.SplitHostPort(origDomain); err == nil {
				origDomain = h
			}
			if origDomain == "" {
				origDomain = "unknown"
			}
			telemetry.RequestsByDomainTotal.WithLabelValues(origDomain).Inc()
			telemetry.RequestBytesByDomainTotal.WithLabelValues(origDomain, "in").Add(float64(reqInSize + 256))
			telemetry.RequestBytesByDomainTotal.WithLabelValues(origDomain, "out").Add(float64(respOutSize + 200))
			telemetry.RecordDomainRequest(origDomain, duration.Seconds(), totalBandwidthBytes)

			// Protocol metrics
			protocol := "http1"
			if r.ProtoMajor == 2 {
				protocol = "http2"
			} else if r.ProtoMajor == 3 {
				protocol = "http3"
			}
			if r.TLS != nil && protocol == "http1" {
				// If it's TLS but not identified as h2/h3 by ProtoMajor, it might still be h2/h3 if NegotiatedProtocol is set.
				// This happens with some server implementations where ProtoMajor might still be 1 for h2.
				switch r.TLS.NegotiatedProtocol {
				case "h2":
					protocol = "http2"
				case "h3":
					protocol = "http3"
				}
			}
			telemetry.RequestsByProtocolTotal.WithLabelValues(protocol).Inc()

			// Track response body size
			// Add a baseline of 200 bytes to account for response headers.
			telemetry.RequestBytesTotal.WithLabelValues(activeRouteID, "out").Add(float64(respOutSize + 200))

			// Track TTFB
			if ttfb := sw.TTFB(); ttfb > 0 {
				telemetry.TTFBSeconds.WithLabelValues(activeRouteID).Observe(ttfb.Seconds())
			}
		})
	}
}

// ipFilterData holds pre-parsed IP filter rules optimized for lookups.
type ipFilterData struct {
	exactAllow map[string]struct{}
	cidrAllow  []*net.IPNet
	exactDeny  map[string]struct{}
	cidrDeny   []*net.IPNet
}

func newIPFilterData(allowList, denyList []string) *ipFilterData {
	d := &ipFilterData{
		exactAllow: make(map[string]struct{}),
		exactDeny:  make(map[string]struct{}),
	}
	for _, r := range allowList {
		if _, ipnet, err := net.ParseCIDR(r); err == nil {
			d.cidrAllow = append(d.cidrAllow, ipnet)
		} else {
			d.exactAllow[r] = struct{}{}
		}
	}
	for _, r := range denyList {
		if _, ipnet, err := net.ParseCIDR(r); err == nil {
			d.cidrDeny = append(d.cidrDeny, ipnet)
		} else {
			d.exactDeny[r] = struct{}{}
		}
	}
	return d
}

func (d *ipFilterData) matches(clientIP string) bool {
	// Deny list takes precedence
	if _, ok := d.exactDeny[clientIP]; ok {
		return true
	}
	ip := net.ParseIP(clientIP)
	if ip != nil {
		for _, rule := range d.cidrDeny {
			if rule.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (d *ipFilterData) allowed(clientIP string) bool {
	if len(d.exactAllow) == 0 && len(d.cidrAllow) == 0 {
		return true
	}
	if _, ok := d.exactAllow[clientIP]; ok {
		return true
	}
	ip := net.ParseIP(clientIP)
	if ip != nil {
		for _, rule := range d.cidrAllow {
			if rule.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// IPFilterWithClientIP returns a middleware that filters requests by IP address using the given clientIP resolver.
func IPFilterWithClientIP(allowList, denyList []string, clientIP func(*http.Request) string) Middleware {
	data := newIPFilterData(allowList, denyList)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			remoteAddr := clientIP(r)

			if data.matches(remoteAddr) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			if !data.allowed(remoteAddr) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
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
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
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
