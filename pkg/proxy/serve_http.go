// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"log/slog"
	"net/http"
	"strings"
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
// as a signed-in dashboard user (ADR 0041). A browser sends the session cookie
// to every port on the dashboard's host, so without this every app behind the
// gateway on that host received the admin's session. It is done here, the one
// place every protocol's request passes on its way to a backend -- HTTP/1, h2,
// gRPC and the WebSocket upgrade alike -- and after the route's middlewares,
// which still see the request as the client sent it.
//
// Without a session cookie or a PASETO bearer token this allocates nothing.
func (h *ProxyHandler) withholdManagementCredentials(r *http.Request) {
	mwauth.StripSessionCookie(r.Header)
	if h.sessions == nil {
		return
	}
	token, ok := pasetoLocalBearer(r.Header.Get("Authorization"))
	if !ok {
		return
	}
	// Only a token this gateway's management plane accepts is withheld: an app
	// may use PASETO v4.local tokens of its own, under its own key, and those
	// are its business.
	if _, err := h.sessions.VerifyToken(token); err == nil {
		r.Header.Del("Authorization")
	}
}

// pasetoLocalBearer returns the token of a "Bearer v4.local." credential, the
// only form a management session token takes.
func pasetoLocalBearer(header string) (string, bool) {
	const scheme, prefix = "bearer ", "v4.local."
	if len(header) <= len(scheme)+len(prefix) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	token := header[len(scheme):]
	return token, strings.HasPrefix(token, prefix)
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
