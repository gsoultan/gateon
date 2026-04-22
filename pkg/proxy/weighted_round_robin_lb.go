package proxy

import (
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

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
		lb.targets[i] = newTargetStateFromTarget(t)
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
