package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

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

// LoadBalancer defines the interface for selecting backend targets.
type LoadBalancer interface {
	Next() string
	NextState() *targetState
	UpdateWeightedTargets(targets []*gateonv1.Target)
	GetStats() []TargetStats
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
	n := atomic.AddUint64(&lb.current, 1)
	return targets[(n-1)%uint64(len(targets))]
}

func (lb *RoundRobinLB) UpdateWeightedTargets(targets []*gateonv1.Target) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.targets = make([]*targetState, len(targets))
	for i, t := range targets {
		lb.targets[i] = &targetState{url: t.Url, alive: true, weight: t.Weight}
	}
}

func (lb *RoundRobinLB) GetStats() []TargetStats {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	stats := make([]TargetStats, len(lb.targets))
	for i, t := range lb.targets {
		avg := uint64(0)
		if atomic.LoadUint64(&t.requestCount) > 0 {
			avg = atomic.LoadUint64(&t.latencySumMs) / atomic.LoadUint64(&t.requestCount)
		}
		stats[i] = TargetStats{
			URL:          t.url,
			Alive:        t.alive,
			RequestCount: atomic.LoadUint64(&t.requestCount),
			ErrorCount:   atomic.LoadUint64(&t.errorCount),
			AvgLatencyMs: avg,
			ActiveConn:   atomic.LoadInt32(&t.activeConn),
		}
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
		return lb.targets[0]
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

func (lb *LeastConnLB) GetStats() []TargetStats {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	stats := make([]TargetStats, len(lb.targets))
	for i, t := range lb.targets {
		avg := uint64(0)
		if atomic.LoadUint64(&t.requestCount) > 0 {
			avg = atomic.LoadUint64(&t.latencySumMs) / atomic.LoadUint64(&t.requestCount)
		}
		stats[i] = TargetStats{
			URL:          t.url,
			Alive:        t.alive,
			RequestCount: atomic.LoadUint64(&t.requestCount),
			ErrorCount:   atomic.LoadUint64(&t.errorCount),
			AvgLatencyMs: avg,
			ActiveConn:   atomic.LoadInt32(&t.activeConn),
		}
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
		return lb.targets[0]
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

func (lb *WeightedRoundRobinLB) GetStats() []TargetStats {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	stats := make([]TargetStats, len(lb.targets))
	for i, t := range lb.targets {
		avg := uint64(0)
		if atomic.LoadUint64(&t.requestCount) > 0 {
			avg = atomic.LoadUint64(&t.latencySumMs) / atomic.LoadUint64(&t.requestCount)
		}
		stats[i] = TargetStats{
			URL:          t.url,
			Alive:        t.alive,
			RequestCount: atomic.LoadUint64(&t.requestCount),
			ErrorCount:   atomic.LoadUint64(&t.errorCount),
			AvgLatencyMs: avg,
			ActiveConn:   atomic.LoadInt32(&t.activeConn),
		}
	}
	return stats
}

// ProxyHandler handles the proxying of requests to backend services.
type ProxyHandler struct {
	lb              LoadBalancer
	routeType       string
	healthCheckPath string
	stopHealthCheck chan struct{}
	transport       http.RoundTripper
}

// NewProxyHandler creates a new ProxyHandler based on the route and its linked service.
func NewProxyHandler(rt *gateonv1.Route, serviceRegistry *config.ServiceRegistry) *ProxyHandler {
	var lb LoadBalancer
	var healthCheckPath string
	var targets []*gateonv1.Target

	if rt.ServiceId != "" && serviceRegistry != nil {
		if svc, ok := serviceRegistry.Get(rt.ServiceId); ok {
			targets = svc.WeightedTargets
			healthCheckPath = svc.HealthCheckPath

			targetUrls := make([]string, len(targets))
			for i, t := range targets {
				targetUrls[i] = t.Url
			}

			switch strings.ToLower(svc.LoadBalancerPolicy) {
			case "least_conn":
				lb = NewLeastConnLB(targetUrls)
			case "weighted_round_robin":
				lb = NewWeightedRoundRobinLB(targets)
			default:
				lb = NewRoundRobinLB(targetUrls)
			}
		}
	}

	if lb == nil {
		lb = NewRoundRobinLB([]string{})
	}

	// Use h2c transport if any target uses h2c://, or h3 if h3://
	useH2 := false
	useH2C := false
	useH3 := false
	for _, t := range targets {
		lowerURL := strings.ToLower(t.Url)
		if strings.HasPrefix(lowerURL, "h2c://") {
			useH2C = true
		}
		if strings.HasPrefix(lowerURL, "h2://") {
			useH2 = true
		}
		if strings.HasPrefix(lowerURL, "h3://") {
			useH3 = true
		}
	}

	var transport http.RoundTripper
	if useH3 {
		transport = &http3.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else if useH2C {
		transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}
	} else if useH2 {
		transport = &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConns = 10000
		t.MaxIdleConnsPerHost = 1000
		t.IdleConnTimeout = 90 * time.Second
		t.ForceAttemptHTTP2 = true
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		transport = t
	}

	h := &ProxyHandler{
		lb:              lb,
		routeType:       rt.Type,
		healthCheckPath: healthCheckPath,
		stopHealthCheck: make(chan struct{}),
		transport:       transport,
	}

	if h.healthCheckPath != "" && len(targets) > 0 {
		targetUrls := make([]string, len(targets))
		for i, t := range targets {
			targetUrls[i] = t.Url
		}
		go h.runHealthCheck(targetUrls)
	}

	return h
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

				var state *targetState
				if rlb, ok := h.lb.(*RoundRobinLB); ok {
					for _, t := range rlb.targets {
						if t.url == u {
							state = t
						}
					}
				} else if lclb, ok := h.lb.(*LeastConnLB); ok {
					for _, t := range lclb.targets {
						if t.url == u {
							state = t
						}
					}
				} else if wrrlb, ok := h.lb.(*WeightedRoundRobinLB); ok {
					for _, t := range wrrlb.targets {
						if t.url == u {
							state = t
						}
					}
				}

				if state != nil {
					alive := err == nil && resp != nil && resp.StatusCode < 500
					state.alive = alive
					if resp != nil {
						resp.Body.Close()
					}
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

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = h.transport
	proxy.BufferPool = bufferPool
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		atomic.AddUint64(&state.errorCount, 1)
		w.WriteHeader(http.StatusBadGateway)
	}

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
