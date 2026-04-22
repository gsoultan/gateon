package proxy

import (
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

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
		lb.targets[i] = newTargetStateFromTarget(t)
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
