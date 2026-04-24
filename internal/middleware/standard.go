package middleware

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

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

			sw := GetStatusResponseWriter(w)
			defer PutStatusResponseWriter(sw)

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
			var pooled bool
			if !ok {
				sw = GetStatusResponseWriter(w)
				w = sw
				pooled = true
			}
			if pooled {
				defer PutStatusResponseWriter(sw)
			}

			next.ServeHTTP(sw, r)

			respOutSize := sw.BytesWritten
			if respOutSize < 0 {
				respOutSize = 0
			}
			totalBandwidthBytes := uint64(reqInSize+256) + uint64(respOutSize+200)

			duration := time.Since(start)
			telemetry.RecordPathRequest(origHost, origPath, duration.Seconds(), totalBandwidthBytes)

			// IP-based metrics
			clientIP := request.GetClientIP(r, request.TrustCloudflareFromEnv())

			// Behavioral Fingerprinting
			fingerprint := ""
			if gc := config.GetGlobalConfig(); gc != nil && gc.AnomalyDetection != nil && gc.AnomalyDetection.EnableBehavioralFingerprinting {
				fp := telemetry.GenerateFingerprint(r)
				fingerprint = fp.Hash
			}

			status := getStatusString(sw.Status)
			country := request.GetCountry(r)
			if sw.Country != "" {
				country = sw.Country
			}

			id := request.GetID(r)
			if debug, ok := r.Context().Value(DebugInfoContextKey).(*DebugInfo); ok && debug != nil {
				telemetry.RecordTraceDetailed(
					id,
					method+" "+origPath,
					activeRouteID,
					float64(duration.Nanoseconds())/1e6,
					start,
					status,
					origPath,
					clientIP,
					fingerprint,
					country,
					r.UserAgent(),
					method,
					r.Referer(),
					origHost+r.URL.RequestURI(),
					"", // JA3
					debug.RequestHeaders,
					debug.RequestBody,
					debug.ResponseHeaders,
					debug.ResponseBody,
				)
			} else {
				telemetry.RecordTrace(
					id,
					method+" "+origPath,
					activeRouteID,
					float64(duration.Nanoseconds())/1e6,
					start,
					status,
					origPath,
					clientIP,
					fingerprint,
					country,
					r.UserAgent(),
					method,
					r.Referer(),
					origHost+r.URL.RequestURI(),
					"", // JA3
				)
			}

			statusStr := getStatusString(sw.Status)

			// Rich Prometheus metrics
			telemetry.RequestsTotal.WithLabelValues(activeRouteID, serviceID, method, statusStr).Inc()
			telemetry.RequestDurationSeconds.WithLabelValues(activeRouteID, serviceID, method).Observe(duration.Seconds())

			telemetry.RequestsByIPTotal.WithLabelValues(clientIP).Inc()
			telemetry.RequestBytesByIPTotal.WithLabelValues(clientIP, "in").Add(float64(reqInSize + 256))
			telemetry.RequestBytesByIPTotal.WithLabelValues(clientIP, "out").Add(float64(respOutSize + 200))

			// Country-based metrics
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
			h := httputil.StripPort(r.Host)

			if !strings.EqualFold(h, host) {
				http.Error(w, "Forbidden: Invalid Host", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

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

type bodyRecorder struct {
	http.ResponseWriter
	body    *bytes.Buffer
	maxSize int
}

func (r *bodyRecorder) Write(b []byte) (int, error) {
	if r.body.Len() < r.maxSize {
		toWrite := min(len(b), r.maxSize-r.body.Len())
		r.body.Write(b[:toWrite])
	}
	return r.ResponseWriter.Write(b)
}

func (r *bodyRecorder) WriteHeader(status int) {
	r.ResponseWriter.WriteHeader(status)
}

var bodyRecorderPool = sync.Pool{
	New: func() any {
		return &bodyRecorder{
			body: new(bytes.Buffer),
		}
	},
}

func Debugger(globalStore config.GlobalConfigStore) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conf := globalStore.Get(r.Context())
			if conf == nil || conf.Debugger == nil || !conf.Debugger.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			maxBodySize := int(conf.Debugger.MaxBodySize)
			if maxBodySize <= 0 {
				maxBodySize = 64 * 1024
			}

			// Capture Request Body
			var reqBody []byte
			if r.Body != nil {
				reqBody, _ = io.ReadAll(io.LimitReader(r.Body, int64(maxBodySize)))
				r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
			}

			reqHeaders, _ := json.Marshal(flattenHeaders(r.Header))

			// Wrap ResponseWriter
			rec := bodyRecorderPool.Get().(*bodyRecorder)
			rec.ResponseWriter = w
			rec.body.Reset()
			rec.maxSize = maxBodySize
			defer bodyRecorderPool.Put(rec)

			r = r.WithContext(context.WithValue(r.Context(), DebugInfoContextKey, &DebugInfo{
				RequestHeaders: string(reqHeaders),
				RequestBody:    string(reqBody),
			}))

			next.ServeHTTP(rec, r)

			respHeaders, _ := json.Marshal(flattenHeaders(rec.Header()))
			debugInfo := r.Context().Value(DebugInfoContextKey).(*DebugInfo)
			debugInfo.ResponseHeaders = string(respHeaders)
			debugInfo.ResponseBody = rec.body.String()
		})
	}
}

func flattenHeaders(h http.Header) map[string]string {
	m := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			m[k] = strings.Join(v, ", ")
		}
	}
	return m
}
