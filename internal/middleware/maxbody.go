package middleware

import (
	"net/http"
	"os"
	"strconv"

	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	bufferingRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateon_buffering_rejected_total",
		Help: "Total number of requests rejected by buffering/max body limits",
	}, []string{"reason"})
)

// DefaultMaxRequestBodySize is 10MB when GATEON_MAX_REQUEST_BODY_SIZE is unset.
const DefaultMaxRequestBodySize = 10 * 1024 * 1024

// MaxBodySizeFromEnv returns max body size in bytes from GATEON_MAX_REQUEST_BODY_SIZE.
// 0 or unset means no limit. Set to a positive value (e.g. 10485760 for 10MB) to enable.
func MaxBodySizeFromEnv() int64 {
	s := os.Getenv("GATEON_MAX_REQUEST_BODY_SIZE")
	if s == "" {
		return DefaultMaxRequestBodySize
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return DefaultMaxRequestBodySize
	}
	return n
}

// MaxBodySize limits the request body size using http.MaxBytesReader.
// Bodies exceeding max return 413 Request Entity Too Large.
func MaxBodySize(max int64) Middleware {
	if max <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			sw, ok := w.(*StatusResponseWriter)
			if !ok {
				sw = &StatusResponseWriter{ResponseWriter: w, Status: http.StatusOK}
				w = sw
			}
			if r.Body != nil {
				r.Body = http.MaxBytesReader(sw, r.Body, max)
			}
			next.ServeHTTP(w, r)
			if sw.Status == http.StatusRequestEntityTooLarge {
				if !ShouldSkipMetrics(r) {
					bufferingRejectedTotal.WithLabelValues("max_request_body_bytes").Inc()
					telemetry.IncBufferingRejected()
				}
			}
		})
	}
}
