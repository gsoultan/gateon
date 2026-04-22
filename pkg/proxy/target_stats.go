package proxy

import (
	"sync/atomic"
)

// CircuitState represents circuit breaker state for a target.
const (
	CircuitClosed   = "CLOSED"    // healthy, accepting traffic
	CircuitOpen     = "OPEN"      // failing, not accepting traffic
	CircuitHalfOpen = "HALF-OPEN" // testing recovery
)

type TargetStats struct {
	URL          string `json:"url"`
	Alive        bool   `json:"alive"`
	CircuitState string `json:"circuit_state"` // CLOSED, OPEN, HALF-OPEN
	RequestCount uint64 `json:"request_count"`
	ErrorCount   uint64 `json:"error_count"`
	AvgLatencyMs uint64 `json:"avg_latency_ms"`
	ActiveConn   int32  `json:"active_conn"`
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
