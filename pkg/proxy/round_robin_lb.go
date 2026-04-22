package proxy

import (
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// RoundRobinLB implements simple round-robin load balancing.
type RoundRobinLB struct {
	targets []*targetState
	current uint64
	mu      sync.RWMutex
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
		lb.targets[i] = newTargetStateFromTarget(t)
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
