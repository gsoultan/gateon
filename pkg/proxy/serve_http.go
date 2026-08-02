// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package proxy

import (
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/pkg/httputil"
)

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	state := h.lb.NextState()
	if state == nil || state.url == "" {
		http.Error(w, "no targets available for service", http.StatusBadGateway)
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

	if isUpgradeRequest(r) {
		h.proxyUpgrade(w, r, targetURL, state, start)
		return
	}

	sw, ok := w.(*httputil.StatusResponseWriter)
	var pooled bool
	if !ok {
		sw = httputil.GetStatusResponseWriter(w)
		w = sw
		pooled = true
	}
	if pooled {
		defer httputil.PutStatusResponseWriter(sw)
	}

	proxy := h.getOrCreateProxy(state)
	proxy.ServeHTTP(sw, r)

	h.recordMetrics(state, start, sw.Status)
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
