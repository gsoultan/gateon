// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	mwauth "github.com/gsoultan/gateon/internal/middleware/auth"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/pkg/httputil"
)

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	state := h.lb.NextState()
	if state == nil || state.url == "" {
		// 503, not 502: no backend was asked, so none answered badly. Every
		// target is out of rotation (or the service has none).
		http.Error(w, "no healthy targets available for service", http.StatusServiceUnavailable)
		return
	}

	h.logRequest(r, state.url)

	atomic.AddInt32(&state.activeConn, 1)
	if state.activeConnGuage != nil {
		state.activeConnGuage.Inc()
	}
	defer h.decrementActiveConn(state)

	targetURL := state.parsedURL
	if targetURL == nil {
		http.Error(w, "invalid target URL", http.StatusInternalServerError)
		return
	}

	h.withholdManagementCredentials(r)

	if isUpgradeRequest(r) {
		h.proxyUpgrade(w, r, targetURL, state, start)
		return
	}

	sw, ok := w.(*httputil.StatusResponseWriter)
	var pooled bool
	if !ok {
		sw = httputil.GetStatusResponseWriter(w)
		pooled = true
	}
	if pooled {
		defer httputil.PutStatusResponseWriter(sw)
	}

	proxy := h.getOrCreateProxy(state)
	proxy.ServeHTTP(sw, r)

	h.recordMetrics(state, start, sw.Status)
}

// withholdManagementCredentials removes from r what would let the backend act
// as a signed-in dashboard user or as a scrape client (ADR 0041, 0050). Since
// ADR 0051 the base handler withholds them as a request enters the data plane,
// before route matching and before any route middleware -- forwardauth and
// introspection call out to servers an operator chose -- so by the time a
// request gets here there is normally nothing left to remove. This is the
// second line: it is the one place every protocol's request passes on its way
// to a backend, HTTP/1, h2, gRPC and the WebSocket upgrade alike, and a
// handler that reaches the proxy some other way is still covered.
//
// Without a session cookie or a management bearer token this allocates
// nothing.
func (h *ProxyHandler) withholdManagementCredentials(r *http.Request) {
	mwauth.WithholdManagementCredentials(r.Header, h.sessions)
}

// ManagementSessions is the management plane's session check this handler
// was built with, so the route's middlewares can refuse to send a session on
// (ADR 0051). Nil when it has none.
func (h *ProxyHandler) ManagementSessions() mwauth.TokenVerifier {
	return h.sessions
}

func (h *ProxyHandler) logRequest(r *http.Request, targetURL string) {
	if logger.L.IsEnabled(slog.LevelDebug) {
		logger.L.LogDebug("Forwarding to service target",
			"flow_step", "service_dispatch",
			"request_id", request.GetID(r),
			"target", targetURL)
	}
}

func (h *ProxyHandler) decrementActiveConn(state *targetState) {
	atomic.AddInt32(&state.activeConn, -1)
	if state.activeConnGuage != nil {
		state.activeConnGuage.Dec()
	}
}

func (h *ProxyHandler) recordMetrics(state *targetState, start time.Time, status int) {
	duration := time.Since(start)
	atomic.AddUint64(&state.requestCount, 1)
	atomic.AddUint64(&state.latencySumUs, uint64(duration.Microseconds()))
	if status >= 500 {
		atomic.AddUint64(&state.errorCount, 1)
	}

	// Provide feedback to the load balancer (e.g. for AI-driven predictive LB)
	h.lb.RecordLatency(state.url, duration.Seconds())
}
