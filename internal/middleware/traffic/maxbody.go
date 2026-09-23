// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"net/http"
	"os"
	"strconv"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/pkg/httputil"
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
func MaxBodySize(max int64) kind.Middleware {
	if max <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveWithBodyLimit(next, w, r, max)
		})
	}
}

// exemptFromBodyLimit reports whether a request carries no body worth capping.
//
// A protocol upgrade is the only exemption, and now actually is: the comment
// said so while kind.IsCorsPreflight sat in the same expression. That term let
// any request past the limit for the price of an Origin and an
// Access-Control-Request-Method header, on a method that may carry a body like
// any other -- and a preflight that genuinely has no body is not affected by a
// limit on bodies, so the exemption bought nothing it did not already have.
//
// The upgrade skip used to key off the Upgrade header alone, which the client
// also controls, so any POST that also said `Upgrade: h2c` went past the limit
// -- hence the ContentLength == 0 half, which the client cannot fake without
// actually sending no body. Same shape, same fix.
func exemptFromBodyLimit(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" && r.ContentLength == 0
}

// serveWithBodyLimit is the handler body, named rather than nested. gocognit
// charges a branch by how deeply it sits, and a middleware is two closures
// before it does anything, so every `if` in here used to cost triple.
func serveWithBodyLimit(next http.Handler, w http.ResponseWriter, r *http.Request, max int64) {
	if exemptFromBodyLimit(r) {
		next.ServeHTTP(w, r)
		return
	}

	// defer inside the branch is deliberate: it runs at function return, not
	// block exit, so the pooled writer is returned exactly when it was taken.
	sw, ok := w.(*httputil.StatusResponseWriter)
	if !ok {
		sw = httputil.GetStatusResponseWriter(w)
		defer httputil.PutStatusResponseWriter(sw)
	}

	if r.Body != nil {
		r.Body = http.MaxBytesReader(sw, r.Body, max)
	}
	next.ServeHTTP(sw, r)

	if sw.Status == http.StatusRequestEntityTooLarge && !kind.ShouldSkipMetrics(r) {
		bufferingRejectedTotal.WithLabelValues("max_request_body_bytes").Inc()
		telemetry.IncBufferingRejected()
	}
}
