package telemetry

import (
	"sync/atomic"
)

// LimitStats holds rejection counts for rate limit, inflight, and buffering.
type LimitStats struct {
	RateLimitRejected   map[string]uint64 `json:"rate_limit_rejected"`
	InflightRejected    map[string]uint64 `json:"inflight_rejected"`
	BufferingRejected   map[string]uint64 `json:"buffering_rejected"`
}

var (
	rateLimitLocalRejected  atomic.Uint64
	rateLimitRedisRejected  atomic.Uint64
	inflightMaxConnRejected atomic.Uint64
	inflightPerIPRejected   atomic.Uint64
	bufferingRejected       atomic.Uint64
)

// IncRateLimitRejected increments the rate limit rejection counter.
func IncRateLimitRejected(backend string) {
	if backend == "redis" {
		rateLimitRedisRejected.Add(1)
	} else {
		rateLimitLocalRejected.Add(1)
	}
}

// IncInflightRejected increments the inflight rejection counter.
func IncInflightRejected(reason string) {
	if reason == "max_connections_per_ip" {
		inflightPerIPRejected.Add(1)
	} else {
		inflightMaxConnRejected.Add(1)
	}
}

// IncBufferingRejected increments the buffering rejection counter.
func IncBufferingRejected() {
	bufferingRejected.Add(1)
}

// GetLimitStats returns current limit rejection stats for the API.
func GetLimitStats() LimitStats {
	return LimitStats{
		RateLimitRejected: map[string]uint64{
			"local": rateLimitLocalRejected.Load(),
			"redis": rateLimitRedisRejected.Load(),
		},
		InflightRejected: map[string]uint64{
			"max_connections":        inflightMaxConnRejected.Load(),
			"max_connections_per_ip": inflightPerIPRejected.Load(),
		},
		BufferingRejected: map[string]uint64{
			"max_request_body_bytes": bufferingRejected.Load(),
		},
	}
}

