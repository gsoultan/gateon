package proxy

import (
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// CircuitState represents circuit breaker state for a target.
const (
	CircuitClosed   = "CLOSED"    // healthy, accepting traffic
	CircuitOpen     = "OPEN"      // failing, not accepting traffic
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
	parsedURL    *url.URL // pre-parsed to avoid per-request url.Parse
	cacheKey     string   // pre-computed proxy cache key (scheme://host/path)
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

func newTargetState(rawURL string, weight int32) *targetState {
	ts := &targetState{url: rawURL, alive: true, weight: weight}
	if parsed, err := url.Parse(rawURL); err == nil {
		// Normalize scheme for proxy cache key
		normalized := *parsed
		switch normalized.Scheme {
		case "h2c":
			normalized.Scheme = "http"
		case "h2", "h3":
			normalized.Scheme = "https"
		}
		ts.parsedURL = &normalized
		ts.cacheKey = normalized.Scheme + "://" + normalized.Host + normalized.Path
	}
	return ts
}

func NewRoundRobinLB(urls []string) *RoundRobinLB {
	lb := &RoundRobinLB{targets: make([]*targetState, len(urls))}
	for i, u := range urls {
		lb.targets[i] = newTargetState(u, 1)
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
		lb.targets[i] = newTargetState(t.Url, t.Weight)
	}
}

func (lb *RoundRobinLB) SetAlive(url string, alive bool) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for _, t := range lb.targets {
		if t.url == url {
			if t.alive != alive {
				state := telemetry.CircuitClosed
				if !alive {
					state = telemetry.CircuitOpen
				}
				telemetry.RecordCircuitBreakerEvent(url, state, "health check")
			}
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
		lb.targets[i] = newTargetState(u, 1)
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
		lb.targets[i] = newTargetState(t.Url, t.Weight)
	}
}

func (lb *LeastConnLB) SetAlive(url string, alive bool) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for _, t := range lb.targets {
		if t.url == url {
			if t.alive != alive {
				state := telemetry.CircuitClosed
				if !alive {
					state = telemetry.CircuitOpen
				}
				telemetry.RecordCircuitBreakerEvent(url, state, "health check")
			}
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
		lb.targets[i] = newTargetState(t.Url, t.Weight)
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
	return nil // defensive: loop should always return; no alive target
}

func (lb *WeightedRoundRobinLB) UpdateWeightedTargets(targets []*gateonv1.Target) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.targets = make([]*targetState, len(targets))
	for i, t := range targets {
		lb.targets[i] = newTargetState(t.Url, t.Weight)
	}
}

func (lb *WeightedRoundRobinLB) SetAlive(url string, alive bool) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for _, t := range lb.targets {
		if t.url == url {
			if t.alive != alive {
				state := telemetry.CircuitClosed
				if !alive {
					state = telemetry.CircuitOpen
				}
				telemetry.RecordCircuitBreakerEvent(url, state, "health check")
			}
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
