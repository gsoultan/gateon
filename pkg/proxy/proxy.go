package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const flushIntervalImmediate = -1

// context key for passing targetState to shared ErrorHandler
type contextKey int

const targetStateContextKey contextKey = 0

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
	proxyPool           sync.Map // map[targetURL string]*httputil.ReverseProxy
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
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if h.activeConnCount() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
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
func (h *ProxyHandler) getOrCreateProxy(cacheKey string, targetURL *url.URL) *httputil.ReverseProxy {
	if v, ok := h.proxyPool.Load(cacheKey); ok {
		return v.(*httputil.ReverseProxy)
	}
	// Clone target to avoid mutation affecting the cache key
	target := &url.URL{
		Scheme: targetURL.Scheme,
		Host:   targetURL.Host,
		Path:   targetURL.Path,
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = h.transport
	rp.BufferPool = bufferPool
	rp.FlushInterval = flushIntervalImmediate // flush immediately for SSE/streaming
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
		if st, ok := r.Context().Value(targetStateContextKey).(*targetState); ok && st != nil {
			atomic.AddUint64(&st.errorCount, 1)
		}
		routeID := middleware.GetRouteName(r)
		if routeID != "" {
			telemetry.RequestFailuresTotal.WithLabelValues(routeID, "service_down").Inc()
		}
		w.WriteHeader(http.StatusBadGateway)
	}
	if v, loaded := h.proxyPool.LoadOrStore(cacheKey, rp); loaded {
		return v.(*httputil.ReverseProxy)
	}
	return rp
}

func (h *ProxyHandler) GetStats() []TargetStats {
	return h.lb.GetStats()
}
