// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

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
	CircuitState string `json:"circuitState"` // CLOSED, OPEN, HALF-OPEN
	RequestCount uint64 `json:"requestCount"`
	ErrorCount   uint64 `json:"errorCount"`
	AvgLatencyMs uint64 `json:"avgLatencyMs"`
	AvgLatencyUs uint64 `json:"avgLatencyUs"`
	ActiveConn   int32  `json:"activeConn"`
}

func targetStatsFromState(t *targetState) TargetStats {
	avgUs := uint64(0)
	if atomic.LoadUint64(&t.requestCount) > 0 {
		avgUs = atomic.LoadUint64(&t.latencySumUs) / atomic.LoadUint64(&t.requestCount)
	}
	alive := t.alive.Load()
	circuit := CircuitClosed
	if !alive {
		circuit = CircuitOpen
	}
	return TargetStats{
		URL:          t.url,
		Alive:        alive,
		CircuitState: circuit,
		RequestCount: atomic.LoadUint64(&t.requestCount),
		ErrorCount:   atomic.LoadUint64(&t.errorCount),
		AvgLatencyMs: avgUs / 1000,
		AvgLatencyUs: avgUs,
		ActiveConn:   atomic.LoadInt32(&t.activeConn),
	}
}
