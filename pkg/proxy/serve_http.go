package proxy

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
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
	telemetry.ActiveConnections.WithLabelValues(state.url).Inc()
	defer h.decrementActiveConn(state)

	targetURL := state.parsedURL
	if targetURL == nil {
		http.Error(w, "invalid target URL", http.StatusInternalServerError)
		return
	}

	r = h.prepareRequest(r, state, targetURL)

	if isWebSocketRequest(r) {
		h.proxyWebSocket(w, r, targetURL, state, start)
		return
	}

	h.handleGRPCAndHTTP2(r, state.url)

	sw, ok := w.(*middleware.StatusResponseWriter)
	var pooled bool
	if !ok {
		sw = middleware.GetStatusResponseWriter(w)
		w = sw
		pooled = true
	}
	if pooled {
		defer middleware.PutStatusResponseWriter(sw)
	}

	proxy := h.getOrCreateProxy(state.cacheKey, targetURL)
	proxy.ServeHTTP(sw, r)

	h.recordMetrics(state, start, sw.Status)
}

func (h *ProxyHandler) logRequest(r *http.Request, targetURL string) {
	logger.L.Debug().
		Str("flow_step", "service_dispatch").
		Str("request_id", request.GetID(r)).
		Str("target", targetURL).
		Msg("Forwarding to service target")
}

func (h *ProxyHandler) decrementActiveConn(state *targetState) {
	atomic.AddInt32(&state.activeConn, -1)
	telemetry.ActiveConnections.WithLabelValues(state.url).Dec()
}

func (h *ProxyHandler) prepareRequest(r *http.Request, state *targetState, targetURL *url.URL) *http.Request {
	ctx := context.WithValue(r.Context(), targetStateContextKey, state)
	ctx = withClientRemoteAddr(ctx, r.RemoteAddr)
	r = r.WithContext(ctx)

	r.URL.Host = targetURL.Host
	r.URL.Scheme = targetURL.Scheme
	r.Header.Set("X-Forwarded-Host", r.Host)
	if r.TLS != nil {
		r.Header.Set("X-Forwarded-Proto", "https")
	} else {
		r.Header.Set("X-Forwarded-Proto", "http")
	}
	r.Host = targetURL.Host
	return r
}

func (h *ProxyHandler) handleGRPCAndHTTP2(r *http.Request, origURL string) {
	isH2C := strings.HasPrefix(origURL, "h2c://")
	isH3 := strings.HasPrefix(origURL, "h3://")
	contentType := r.Header.Get("Content-Type")
	isGRPC := len(contentType) >= 16 && strings.EqualFold(contentType[:16], "application/grpc")

	if isH3 {
		r.ProtoMajor = 3
		r.ProtoMinor = 0
		r.Proto = "HTTP/3.0"
	} else if isGRPC || isH2C {
		r.ProtoMajor = 2
		r.ProtoMinor = 0
		r.Proto = "HTTP/2.0"
		if isGRPC {
			r.Header.Del("Content-Length")
			r.ContentLength = -1
			if r.Header.Get("TE") == "" {
				r.Header.Set("TE", "trailers")
			}
		}
	}
}

func (h *ProxyHandler) recordMetrics(state *targetState, start time.Time, status int) {
	duration := time.Since(start)
	atomic.AddUint64(&state.requestCount, 1)
	atomic.AddUint64(&state.latencySumMs, uint64(duration.Milliseconds()))
	if status >= 500 {
		atomic.AddUint64(&state.errorCount, 1)
	}
}
