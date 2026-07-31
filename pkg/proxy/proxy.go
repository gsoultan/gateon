package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gateonhttputil "github.com/gsoultan/gateon/internal/httputil"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const flushIntervalImmediate = -1

// context key for passing targetState to shared ErrorHandler
type contextKey int

// ProxyHandler handles the proxying of requests to backend services.
type ProxyHandler struct {
	lb                  LoadBalancer
	routeType           string
	healthCheckPath     string
	healthCheckPort     int32
	healthCheckProtocol string
	healthCheckType     gateonv1.HealthCheckType
	discoveryURL        string
	routeName           string
	stopDiscovery       chan struct{}
	stopHealthCheck     chan struct{}
	closeOnce           sync.Once
	transport           http.RoundTripper
	transportFactory    *backendTransportFactory
	healthCheckClient   *http.Client
	tlsConfig           *tls.Config
	StripCORS           bool
}

// NewProxyHandler creates a ProxyHandler from route and ServiceStore (DIP).
func NewProxyHandler(rt *gateonv1.Route, serviceStore config.ServiceStore) *ProxyHandler {
	return NewProxyHandlerWithOpts(rt, serviceStore, nil, nil)
}

// NewProxyHandlerWithFactory creates a ProxyHandler with an explicit LoadBalancerFactory.
func NewProxyHandlerWithFactory(rt *gateonv1.Route, serviceStore config.ServiceStore, lbFactory LoadBalancerFactory) *ProxyHandler {
	return NewProxyHandlerWithOpts(rt, serviceStore, lbFactory, nil)
}

// NewProxyHandlerWithOpts creates a ProxyHandler with optional LB factory and transport config.
func NewProxyHandlerWithOpts(rt *gateonv1.Route, serviceStore config.ServiceStore, lbFactory LoadBalancerFactory, transportConfig *TransportConfig) *ProxyHandler {
	b := NewProxyHandlerBuilder(rt, serviceStore, lbFactory)
	if transportConfig != nil {
		b.SetTransportConfig(transportConfig)
	}
	return b.Build()
}

func (h *ProxyHandler) Close() {
	h.closeOnce.Do(func() {
		if h.stopDiscovery != nil {
			close(h.stopDiscovery)
		}
		close(h.stopHealthCheck)
		if h.transportFactory != nil {
			h.transportFactory.Close()
		}
		if c, ok := h.transport.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	})
}

// DrainAndClose waits for in-flight requests to complete (up to timeout), then closes.
func (h *ProxyHandler) DrainAndClose(timeout time.Duration) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		if h.activeConnCount() == 0 {
			break
		}
		select {
		case <-ticker.C:
			continue
		case <-timer.C:
			h.routeName = h.routeName + " (drain timeout)"
			goto finish
		}
	}

finish:
	h.Close()
}

func (h *ProxyHandler) activeConnCount() int32 {
	var total int32
	for _, s := range h.lb.GetStats() {
		total += s.ActiveConn
	}
	return total
}

// getOrCreateProxy returns a cached ReverseProxy for the target, creating one if needed.
func (h *ProxyHandler) getOrCreateProxy(state *targetState) *httputil.ReverseProxy {
	if rp := state.proxy.Load(); rp != nil {
		return rp
	}

	// We use a custom ReverseProxy instead of NewSingleHostReverseProxy to avoid
	// the default director which can be redundant given our prepareRequest.
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			h.rewriteRequest(pr, state)
		},
		Transport: &targetBoundRoundTripper{
			state:   state,
			factory: h.transportFactory,
		},
		BufferPool:    bufferPool,
		FlushInterval: flushIntervalImmediate,
	}

	if h.StripCORS {
		rp.ModifyResponse = func(resp *http.Response) error {
			resp.Header.Del("Access-Control-Allow-Origin")
			resp.Header.Del("Access-Control-Allow-Methods")
			resp.Header.Del("Access-Control-Allow-Headers")
			resp.Header.Del("Access-Control-Exposed-Headers")
			resp.Header.Del("Access-Control-Allow-Credentials")
			resp.Header.Del("Access-Control-Max-Age")
			return nil
		}
	}

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) {
			w.WriteHeader(499)
			return
		}

		status := http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}

		atomic.AddUint64(&state.errorCount, 1)
		routeID := middleware.GetRouteName(r)
		if routeID != "" {
			telemetry.RequestFailuresTotal.WithLabelValues(routeID, "service_down").Inc()
		}
		logger.L.LogError("Proxy error",
			"error", err,
			"target", state.url,
			"route", routeID,
			"method", r.Method,
			"path", r.URL.Path,
			"request_id", request.GetID(r))
		w.WriteHeader(status)
	}

	if state.proxy.CompareAndSwap(nil, rp) {
		return rp
	}
	return state.proxy.Load()
}

func (h *ProxyHandler) GetStats() []TargetStats {
	return h.lb.GetStats()
}

func (h *ProxyHandler) rewriteRequest(pr *httputil.ProxyRequest, state *targetState) {
	targetURL := state.parsedURL
	if targetURL == nil {
		return
	}

	// 1. Copy essential headers and set forward headers
	pr.Out.URL.Scheme = targetURL.Scheme
	pr.Out.URL.Host = targetURL.Host
	pr.Out.URL.Path = gateonhttputil.SingleJoiningSlash(targetURL.Path, pr.In.URL.Path)
	pr.Out.URL.RawQuery = pr.In.URL.RawQuery

	pr.Out.Host = targetURL.Host

	clientIP := request.GetClientIP(pr.In, false)
	pr.Out.Header.Set("X-Real-IP", clientIP)
	if xff := pr.In.Header.Get("X-Forwarded-For"); xff != "" {
		pr.Out.Header.Set("X-Forwarded-For", xff+", "+clientIP)
	} else {
		pr.Out.Header.Set("X-Forwarded-For", clientIP)
	}
	pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
	scheme := request.Scheme(pr.In)
	pr.Out.Header.Set("X-Forwarded-Proto", scheme)
	if scheme == "https" {
		pr.Out.Header.Set("X-Forwarded-Ssl", "on")
	}
	if ja4 := telemetry.GetCachedJA4H(pr.In); ja4 != "" {
		pr.Out.Header.Set("X-Gateon-JA4", ja4)
	}

	// 2. Handle gRPC and HTTP/2 protocol specifics
	origURL := state.url
	isH2C := strings.HasPrefix(origURL, "h2c://")
	isH3 := strings.HasPrefix(origURL, "h3://")
	isHTTPS := strings.HasPrefix(origURL, "https://") || strings.HasPrefix(origURL, "h2://")
	contentType := pr.In.Header.Get("Content-Type")
	isGRPC := len(contentType) >= 16 && strings.EqualFold(contentType[:16], "application/grpc")

	if isH3 {
		pr.Out.ProtoMajor = 3
		pr.Out.ProtoMinor = 0
		pr.Out.Proto = "HTTP/3.0"
	} else if isGRPC || isH2C {
		if isH2C || isHTTPS {
			pr.Out.ProtoMajor = 2
			pr.Out.ProtoMinor = 0
			pr.Out.Proto = "HTTP/2.0"
		}
		if isGRPC {
			pr.Out.Header.Del("Content-Length")
			pr.Out.ContentLength = -1
			if pr.Out.Header.Get("TE") == "" {
				pr.Out.Header.Set("TE", "trailers")
			}
		}
	}

	// 3. PROXY Protocol support
	if state.proxyProtocolEnabled {
		pr.Out = pr.Out.WithContext(withClientRemoteAddr(pr.Out.Context(), pr.In.RemoteAddr))
	}

	// 4. Ensure User-Agent isn't automatically set by Go's default if missing
	if _, ok := pr.In.Header["User-Agent"]; !ok {
		pr.Out.Header.Set("User-Agent", "")
	}
}
