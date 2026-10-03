// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// CircuitState represents circuit breaker state for a target.
const (
	CircuitClosed   = "CLOSED"    // healthy, accepting traffic
	CircuitOpen     = "OPEN"      // failing, not accepting traffic
	CircuitHalfOpen = "HALF-OPEN" // testing recovery
)

type TargetStats struct {
	URL   string `json:"url"`
	Alive bool   `json:"alive"`
	// CircuitState is whether requests reach this target: OPEN when its health
	// check took it out of rotation or the route's circuit breaker is open,
	// HALF-OPEN while that breaker probes, CLOSED otherwise.
	CircuitState string `json:"circuitState"`
	// Breaker is the route's circuit breaker state, empty when the route has
	// none.
	Breaker      string `json:"breaker,omitempty"`
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

// withBreaker folds the circuit breaker kept under key -- the route's ID, when
// the route has one -- into every target's row. The rows used to derive their
// state from the health check alone, so an open breaker refusing the route's
// every request read CLOSED, and the page's OPEN filter hid it (ADR 0047).
func withBreaker(stats []TargetStats, key string) []TargetStats {
	if key == "" {
		return stats
	}
	state, ok := middleware.CircuitStateOf(key)
	if !ok {
		return stats
	}
	for i := range stats {
		stats[i].Breaker = string(state)
		if stats[i].CircuitState == CircuitClosed {
			stats[i].CircuitState = string(state)
		}
	}
	return stats
}

// TallyTargets adds stats to c. It is the one place the dashboard's target
// counts are classified, shared by /v1/diag/agg-stats and the realtime
// snapshot so the two cannot disagree about what a target is.
func TallyTargets(stats []TargetStats, c *telemetry.TargetHealthCounts) {
	for _, s := range stats {
		c.Total++
		if s.Alive {
			c.Healthy++
		} else {
			c.Down++
		}
	}
}
