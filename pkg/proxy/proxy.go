package proxy

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gateon/gateon/internal/config"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

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
	return p.pool.Get().([]byte)
}

func (p *syncBufferPool) Put(b []byte) {
	p.pool.Put(b)
}

// CircuitState represents circuit breaker state for a target.
const (
	CircuitClosed   = "CLOSED"   // healthy, accepting traffic
	CircuitOpen     = "OPEN"     // failing, not accepting traffic
	CircuitHalfOpen = "HALF-OPEN" // testing recovery
)

// LoadBalancer defines the interface for selecting backend targets.
type LoadBalancer interface {
	Next() string
	NextState() *targetState
	UpdateWeightedTargets(targets []*gateonv1.Target)
	GetStats() []TargetStats
	SetAlive(url string, alive bool)
}

type targetState struct {
	url          string
	weight       int32
	alive        bool
	requestCount uint64
	errorCount   uint64
	latencySumMs uint64
	activeConn   int32
}

type TargetStats struct {
	URL          string `json:"url"`
	Alive        bool   `json:"alive"`
	CircuitState string `json:"circuit_state"` // CLOSED, OPEN, HALF-OPEN
	RequestCount uint64 `json:"request_count"`
	ErrorCount   uint64 `json:"error_count"`
	AvgLatencyMs uint64 `json:"avg_latency_ms"`
	ActiveConn   int32  `json:"active_conn"`
}

// RoundRobinLB implements simple round-robin load balancing.
type RoundRobinLB struct {
	targets []*targetState
	current uint64
	mu      sync.RWMutex
}

func NewRoundRobinLB(urls []string) *RoundRobinLB {
	lb := &RoundRobinLB{targets: make([]*targetState, len(urls))}
	for i, u := range urls {
		lb.targets[i] = &targetState{url: u, alive: true, weight: 1}
	}
	return lb
}

func (lb *RoundRobinLB) Next() string {
	s := lb.NextState()
	if s == nil {
		return ""
	}
	return s.url
}

func (lb *RoundRobinLB) NextState() *targetState {
	lb.mu.RLock()
	targets := lb.targets
	lb.mu.RUnlock()

	if len(targets) == 0 {
		return nil
	}
	// Round-robin among alive targets only (circuit breaker: skip OPEN targets)
	n := atomic.AddUint64(&lb.current, 1)
	start := (n - 1) % uint64(len(targets))
	for i := uint64(0); i < uint64(len(targets)); i++ {
		idx := (start + i) % uint64(len(targets))
		t := targets[idx]
		if t.alive {
			return t
		}
	}
	return nil // no alive targets
}

func (lb *RoundRobinLB) UpdateWeightedTargets(targets []*gateonv1.Target) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.targets = make([]*targetState, len(targets))
	for i, t := range targets {
		lb.targets[i] = &targetState{url: t.Url, alive: true, weight: t.Weight}
	}
}

func (lb *RoundRobinLB) SetAlive(url string, alive bool) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for _, t := range lb.targets {
		if t.url == url {
			t.alive = alive
			return
		}
	}
}

func (lb *RoundRobinLB) GetStats() []TargetStats {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	stats := make([]TargetStats, len(lb.targets))
	for i, t := range lb.targets {
		stats[i] = targetStatsFromState(t)
	}
	return stats
}

// LeastConnLB implements least connections load balancing.
type LeastConnLB struct {
	targets []*targetState
	mu      sync.RWMutex
}

func NewLeastConnLB(urls []string) *LeastConnLB {
	lb := &LeastConnLB{targets: make([]*targetState, len(urls))}
	for i, u := range urls {
		lb.targets[i] = &targetState{url: u, alive: true, weight: 1}
	}
	return lb
}

func (lb *LeastConnLB) Next() string {
	s := lb.NextState()
	if s == nil {
		return ""
	}
	return s.url
}

func (lb *LeastConnLB) NextState() *targetState {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	if len(lb.targets) == 0 {
		return nil
	}
	var best *targetState
	for _, t := range lb.targets {
		if !t.alive {
			continue
		}
		if best == nil || atomic.LoadInt32(&t.activeConn) < atomic.LoadInt32(&best.activeConn) {
			best = t
		}
	}
	if best == nil {
		return nil // no alive targets (circuit breaker: all OPEN)
	}
	return best
}

func (lb *LeastConnLB) UpdateWeightedTargets(targets []*gateonv1.Target) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.targets = make([]*targetState, len(targets))
	for i, t := range targets {
		lb.targets[i] = &targetState{url: t.Url, alive: true, weight: t.Weight}
	}
}

func (lb *LeastConnLB) SetAlive(url string, alive bool) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for _, t := range lb.targets {
		if t.url == url {
			t.alive = alive
			return
		}
	}
}

func (lb *LeastConnLB) GetStats() []TargetStats {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	stats := make([]TargetStats, len(lb.targets))
	for i, t := range lb.targets {
		stats[i] = targetStatsFromState(t)
	}
	return stats
}

// WeightedRoundRobinLB implements weighted round-robin load balancing.
type WeightedRoundRobinLB struct {
	targets []*targetState
	current uint64
	mu      sync.RWMutex
}

func NewWeightedRoundRobinLB(targets []*gateonv1.Target) *WeightedRoundRobinLB {
	lb := &WeightedRoundRobinLB{targets: make([]*targetState, len(targets))}
	for i, t := range targets {
		lb.targets[i] = &targetState{url: t.Url, alive: true, weight: t.Weight}
	}
	return lb
}

func (lb *WeightedRoundRobinLB) Next() string {
	s := lb.NextState()
	if s == nil {
		return ""
	}
	return s.url
}

func (lb *WeightedRoundRobinLB) NextState() *targetState {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	if len(lb.targets) == 0 {
		return nil
	}

	totalWeight := int32(0)
	for _, t := range lb.targets {
		if t.alive {
			totalWeight += t.weight
		}
	}

	if totalWeight <= 0 {
		return nil // no alive targets (circuit breaker: all OPEN)
	}

	n := atomic.AddUint64(&lb.current, 1)
	val := int32((n - 1) % uint64(totalWeight))

	currentSum := int32(0)
	for _, t := range lb.targets {
		if !t.alive {
			continue
		}
		currentSum += t.weight
		if val < currentSum {
			return t
		}
	}
	return lb.targets[0]
}

func (lb *WeightedRoundRobinLB) UpdateWeightedTargets(targets []*gateonv1.Target) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.targets = make([]*targetState, len(targets))
	for i, t := range targets {
		lb.targets[i] = &targetState{url: t.Url, alive: true, weight: t.Weight}
	}
}

func (lb *WeightedRoundRobinLB) SetAlive(url string, alive bool) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for _, t := range lb.targets {
		if t.url == url {
			t.alive = alive
			return
		}
	}
}

func (lb *WeightedRoundRobinLB) GetStats() []TargetStats {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	stats := make([]TargetStats, len(lb.targets))
	for i, t := range lb.targets {
		stats[i] = targetStatsFromState(t)
	}
	return stats
}

func targetStatsFromState(t *targetState) TargetStats {
	avg := uint64(0)
	if atomic.LoadUint64(&t.requestCount) > 0 {
		avg = atomic.LoadUint64(&t.latencySumMs) / atomic.LoadUint64(&t.requestCount)
	}
	circuit := CircuitClosed
	if !t.alive {
		circuit = CircuitOpen
	}
	return TargetStats{
		URL:          t.url,
		Alive:        t.alive,
		CircuitState: circuit,
		RequestCount: atomic.LoadUint64(&t.requestCount),
		ErrorCount:   atomic.LoadUint64(&t.errorCount),
		AvgLatencyMs: avg,
		ActiveConn:   atomic.LoadInt32(&t.activeConn),
	}
}

// context key for passing targetState to shared ErrorHandler
type contextKey int

const targetStateContextKey contextKey = 0

// ProxyHandler handles the proxying of requests to backend services.
type ProxyHandler struct {
	lb              LoadBalancer
	routeType       string
	healthCheckPath string
	stopHealthCheck chan struct{}
	transport       http.RoundTripper
	proxyPool       sync.Map // map[targetURL string]*httputil.ReverseProxy
}

// NewProxyHandler creates a ProxyHandler from route and ServiceStore (DIP).
func NewProxyHandler(rt *gateonv1.Route, serviceStore config.ServiceStore) *ProxyHandler {
	return NewProxyHandlerWithFactory(rt, serviceStore, nil)
}

// NewProxyHandlerWithFactory creates a ProxyHandler with an explicit LoadBalancerFactory.
func NewProxyHandlerWithFactory(rt *gateonv1.Route, serviceStore config.ServiceStore, lbFactory LoadBalancerFactory) *ProxyHandler {
	return NewProxyHandlerBuilder(rt, serviceStore, lbFactory).Build()
}

func (h *ProxyHandler) runHealthCheck(urls []string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: h.transport,
	}

	for {
		select {
		case <-ticker.C:
			for _, u := range urls {
				uForHealth := u
				if strings.HasPrefix(u, "h2c://") {
					uForHealth = "http://" + strings.TrimPrefix(u, "h2c://")
				} else if strings.HasPrefix(u, "h2://") || strings.HasPrefix(u, "h3://") {
					uForHealth = "https://" + strings.TrimPrefix(strings.TrimPrefix(u, "h2://"), "h3://")
				}
				fullURL := strings.TrimSuffix(uForHealth, "/") + h.healthCheckPath
				resp, err := client.Get(fullURL)
				alive := err == nil && resp != nil && resp.StatusCode < 500
				h.lb.SetAlive(u, alive)
				if resp != nil {
					resp.Body.Close()
				}
			}
		case <-h.stopHealthCheck:
			return
		}
	}
}

func (h *ProxyHandler) Close() {
	close(h.stopHealthCheck)
	if c, ok := h.transport.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

// getOrCreateProxy returns a cached ReverseProxy for the target, creating one if needed.
// Reusing proxies avoids per-request allocations at high throughput (100k+ req/s).
func (h *ProxyHandler) getOrCreateProxy(targetURL *url.URL) *httputil.ReverseProxy {
	key := targetURL.String()
	if v, ok := h.proxyPool.Load(key); ok {
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
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if st, ok := r.Context().Value(targetStateContextKey).(*targetState); ok && st != nil {
			atomic.AddUint64(&st.errorCount, 1)
		}
		w.WriteHeader(http.StatusBadGateway)
	}
	if v, loaded := h.proxyPool.LoadOrStore(key, rp); loaded {
		return v.(*httputil.ReverseProxy)
	}
	return rp
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	state := h.lb.NextState()
	if state == nil || state.url == "" {
		http.Error(w, "no targets available for service", http.StatusBadGateway)
		return
	}

	atomic.AddInt32(&state.activeConn, 1)
	defer atomic.AddInt32(&state.activeConn, -1)

	targetURL, err := url.Parse(state.url)
	if err != nil {
		http.Error(w, "invalid target URL", http.StatusInternalServerError)
		return
	}

	isH2 := targetURL.Scheme == "h2"
	isH2C := targetURL.Scheme == "h2c"
	isH3 := targetURL.Scheme == "h3"
	if isH2C {
		targetURL.Scheme = "http"
	} else if isH3 || isH2 {
		targetURL.Scheme = "https"
	}

	// Pass state via context for shared ErrorHandler
	ctx := context.WithValue(r.Context(), targetStateContextKey, state)
	r = r.WithContext(ctx)

	proxy := h.getOrCreateProxy(targetURL)

	// Update request headers for proxying
	r.URL.Host = targetURL.Host
	r.URL.Scheme = targetURL.Scheme
	r.Header.Set("X-Forwarded-Host", r.Host)
	r.Host = targetURL.Host

	// Handle gRPC metadata translation or h2c/h3
	isGRPC := strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
	if isH3 {
		r.ProtoMajor = 3
		r.ProtoMinor = 0
	} else if isGRPC || isH2C {
		r.ProtoMajor = 2
		r.ProtoMinor = 0
	}

	srw := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
	proxy.ServeHTTP(srw, r)

	duration := time.Since(start)
	atomic.AddUint64(&state.requestCount, 1)
	atomic.AddUint64(&state.latencySumMs, uint64(duration.Milliseconds()))
	if srw.status >= 500 {
		atomic.AddUint64(&state.errorCount, 1)
	}
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
