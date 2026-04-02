package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/discovery"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const flushIntervalImmediate = -1

var bufferPool = &syncBufferPool{
	pool: sync.Pool{
		New: func() any {
			return make([]byte, 32*1024)
		},
	},
}

type syncBufferPool struct {
	pool sync.Pool
}

func (p *syncBufferPool) Get() []byte {
	b := p.pool.Get()
	if b == nil {
		return make([]byte, 32*1024)
	}
	return b.([]byte)
}

func (p *syncBufferPool) Put(b []byte) {
	p.pool.Put(b)
}

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
	healthCheckClient   *http.Client
	tlsConfig           *tls.Config
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

func (h *ProxyHandler) runHealthCheck(urls []string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	client := h.healthCheckClient
	if client == nil {
		client = &http.Client{
			Timeout:   5 * time.Second,
			Transport: h.transport,
		}
	}

	for {
		select {
		case <-ticker.C:
			currentStats := h.lb.GetStats()
			for _, s := range currentStats {
				u := s.URL
				var alive bool
				if h.healthCheckType == gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_GRPC {
					alive = h.checkGRPCHealth(context.Background(), u)
				} else {
					healthURL := h.buildHealthCheckURL(u)
					resp, err := client.Get(healthURL)
					alive = err == nil && resp != nil && resp.StatusCode < 500
					if resp != nil {
						resp.Body.Close()
					}
				}
				h.lb.SetAlive(u, alive)
				// Update Prometheus target health gauge
				healthVal := 0.0
				if alive {
					healthVal = 1.0
				}
				telemetry.TargetHealth.WithLabelValues(h.routeName, u).Set(healthVal)
				telemetry.ActiveConnections.WithLabelValues(u).Set(float64(s.ActiveConn))
			}
		case <-h.stopHealthCheck:
			return
		}
	}
}

func (h *ProxyHandler) checkGRPCHealth(ctx context.Context, targetURL string) bool {
	host := targetURL
	useTLS := false
	if strings.HasPrefix(targetURL, "h2c://") {
		host = strings.TrimPrefix(targetURL, "h2c://")
	} else if strings.HasPrefix(targetURL, "h2://") {
		host = strings.TrimPrefix(targetURL, "h2://")
		useTLS = true
	} else if strings.HasPrefix(targetURL, "h3://") {
		host = strings.TrimPrefix(targetURL, "h3://")
		useTLS = true
	}

	// Apply port override if configured
	if h.healthCheckPort > 0 {
		hostOnly, _, err := net.SplitHostPort(host)
		if err == nil {
			host = net.JoinHostPort(hostOnly, fmt.Sprintf("%d", h.healthCheckPort))
		} else {
			// If no port in host, just append it
			host = net.JoinHostPort(host, fmt.Sprintf("%d", h.healthCheckPort))
		}
	}

	var opts []grpc.DialOption
	if useTLS {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(h.tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Set a reasonable timeout for health check dial
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, host, opts...)
	if err != nil {
		return false
	}
	defer conn.Close()

	client := grpc_health_v1.NewHealthClient(conn)
	resp, err := client.Check(dialCtx, &grpc_health_v1.HealthCheckRequest{
		Service: h.healthCheckPath,
	})

	return err == nil && resp != nil && resp.Status == grpc_health_v1.HealthCheckResponse_SERVING
}

// buildHealthCheckURL constructs the health check URL for a given target URL.
// It applies health_check_port and health_check_protocol overrides when configured,
// enabling scenarios like gRPC on port 3000 with HTTP health checks on port 3001.
func (h *ProxyHandler) buildHealthCheckURL(targetURL string) string {
	uForHealth := targetURL
	if strings.HasPrefix(targetURL, "h2c://") {
		uForHealth = "http://" + strings.TrimPrefix(targetURL, "h2c://")
	} else if strings.HasPrefix(targetURL, "h2://") || strings.HasPrefix(targetURL, "h3://") {
		uForHealth = "https://" + strings.TrimPrefix(strings.TrimPrefix(targetURL, "h2://"), "h3://")
	}

	parsed, err := url.Parse(uForHealth)
	if err != nil {
		return strings.TrimSuffix(uForHealth, "/") + h.healthCheckPath
	}

	if h.healthCheckProtocol != "" {
		parsed.Scheme = h.healthCheckProtocol
	}

	if h.healthCheckPort > 0 {
		host := parsed.Hostname()
		parsed.Host = net.JoinHostPort(host, fmt.Sprintf("%d", h.healthCheckPort))
	}

	parsed.Path = h.healthCheckPath
	return parsed.String()
}

func (h *ProxyHandler) runDiscovery() {
	if h.discoveryURL == "" {
		return
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	resolver := discovery.NewResolver()

	for {
		select {
		case <-ticker.C:
			targets, err := resolver.Resolve(context.Background(), h.discoveryURL)
			if err == nil && len(targets) > 0 {
				h.lb.UpdateWeightedTargets(targets)
			}
		case <-h.stopDiscovery:
			return
		}
	}
}

func (h *ProxyHandler) Close() {
	h.closeOnce.Do(func() {
		if h.stopDiscovery != nil {
			close(h.stopDiscovery)
		}
		close(h.stopHealthCheck)
		if c, ok := h.transport.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	})
}

// DrainAndClose waits for in-flight requests to complete (up to timeout), then closes.
// Use for zero-downtime config reload: remove handler from routing first, then DrainAndClose.
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
// Reusing proxies avoids per-request allocations at high throughput (100k+ req/s).
// The cacheKey is pre-computed in targetState to avoid per-request string allocation.
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
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if st, ok := r.Context().Value(targetStateContextKey).(*targetState); ok && st != nil {
			atomic.AddUint64(&st.errorCount, 1)
		}
		w.WriteHeader(http.StatusBadGateway)
	}
	if v, loaded := h.proxyPool.LoadOrStore(cacheKey, rp); loaded {
		return v.(*httputil.ReverseProxy)
	}
	return rp
}

var statusResponseWriterPool = sync.Pool{
	New: func() any {
		return &statusResponseWriter{status: http.StatusOK}
	},
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	state := h.lb.NextState()
	if state == nil || state.url == "" {
		http.Error(w, "no targets available for service", http.StatusBadGateway)
		return
	}

	logger.L.Debug().
		Str("flow_step", "service_dispatch").
		Str("request_id", request.GetID(r)).
		Str("target", state.url).
		Msg("Forwarding to service target")

	atomic.AddInt32(&state.activeConn, 1)
	telemetry.ActiveConnections.WithLabelValues(state.url).Inc()
	defer func() {
		atomic.AddInt32(&state.activeConn, -1)
		telemetry.ActiveConnections.WithLabelValues(state.url).Dec()
	}()

	// Use pre-parsed URL from targetState to avoid per-request url.Parse allocation
	targetURL := state.parsedURL
	if targetURL == nil {
		http.Error(w, "invalid target URL", http.StatusInternalServerError)
		return
	}

	origScheme := state.url
	isH2C := strings.HasPrefix(origScheme, "h2c://")
	isH3 := strings.HasPrefix(origScheme, "h3://")

	// Pass state via context for shared ErrorHandler
	ctx := context.WithValue(r.Context(), targetStateContextKey, state)
	r = r.WithContext(ctx)

	proxy := h.getOrCreateProxy(state.cacheKey, targetURL)

	// Update request headers for proxying
	r.URL.Host = targetURL.Host
	r.URL.Scheme = targetURL.Scheme
	r.Header.Set("X-Forwarded-Host", r.Host)
	if r.TLS != nil {
		r.Header.Set("X-Forwarded-Proto", "https")
	} else {
		r.Header.Set("X-Forwarded-Proto", "http")
	}
	r.Host = targetURL.Host

	// WebSocket: ReverseProxy strips Upgrade/Connection (hop-by-hop). Use hijack tunnel.
	if isWebSocketRequest(r) {
		h.proxyWebSocket(w, r, targetURL, state, start)
		return
	}

	// Handle gRPC metadata translation or h2c/h3
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
			// gRPC requires trailers and no content-length
			r.Header.Del("Content-Length")
			r.ContentLength = -1
			if r.Header.Get("TE") == "" {
				r.Header.Set("TE", "trailers")
			}
		}
	}

	srw := statusResponseWriterPool.Get().(*statusResponseWriter)
	srw.ResponseWriter = w
	srw.status = http.StatusOK

	proxy.ServeHTTP(srw, r)

	duration := time.Since(start)
	atomic.AddUint64(&state.requestCount, 1)
	atomic.AddUint64(&state.latencySumMs, uint64(duration.Milliseconds()))
	if srw.status >= 500 {
		atomic.AddUint64(&state.errorCount, 1)
	}

	srw.ResponseWriter = nil
	statusResponseWriterPool.Put(srw)
}

func (h *ProxyHandler) GetStats() []TargetStats {
	return h.lb.GetStats()
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (w *statusResponseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
