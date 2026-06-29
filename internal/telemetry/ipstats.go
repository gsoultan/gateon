package telemetry

import (
	"sync"
	"sync/atomic"
)

// maxIPBandwidthMapSize bounds the in-memory per-IP bandwidth tracker so that a
// flood of distinct client IPs (e.g. DDoS, spoofed source addresses) cannot grow
// memory without limit. This is the bounded, always-on alternative to the
// GATEON_PER_IP_METRICS Prometheus series, whose {ip} label is an unbounded
// cardinality leak and is therefore opt-in. When the cap is exceeded, ~25% of
// keys are evicted (same bulk-drop policy as evictPathStatsLocked in stats.go).
const (
	numShards              = 16
	maxIPBandwidthPerShard = 64 // total 1024 across all shards
)

var (
	bandwidthShards [numShards]*bandwidthShard
)

type bandwidthShard struct {
	m  map[string]*ipBandwidthInternal
	mu sync.RWMutex
}

func init() {
	for i := range numShards {
		bandwidthShards[i] = &bandwidthShard{
			m: make(map[string]*ipBandwidthInternal),
		}
	}
}

func getBandwidthShard(ip string) *bandwidthShard {
	var h uint64 = 14695981039346656037
	for i := range len(ip) {
		h ^= uint64(ip[i])
		h *= 1099511628211
	}
	return bandwidthShards[h%numShards]
}

type ipBandwidthInternal struct {
	requestCount uint64
	bytesIn      uint64
	bytesOut     uint64
}

// RecordIPBandwidth accumulates cumulative request/byte counts for a client IP.
// It is sharded to reduce mutex contention and bounded to prevent memory leaks.
func RecordIPBandwidth(ip string, bytesIn, bytesOut uint64) {
	if ip == "" {
		return
	}

	shard := getBandwidthShard(ip)
	shard.mu.RLock()
	s, ok := shard.m[ip]
	shard.mu.RUnlock()

	if !ok {
		shard.mu.Lock()
		s, ok = shard.m[ip]
		if !ok {
			if len(shard.m) >= maxIPBandwidthPerShard {
				evictIPBandwidthLocked(shard)
			}
			s = &ipBandwidthInternal{}
			shard.m[ip] = s
		}
		shard.mu.Unlock()
	}

	atomic.AddUint64(&s.requestCount, 1)
	atomic.AddUint64(&s.bytesIn, bytesIn)
	atomic.AddUint64(&s.bytesOut, bytesOut)
}

// getIPBandwidthStats returns a snapshot of the per-IP bandwidth tracker as
// IPMetric values for the metrics snapshot.
func getIPBandwidthStats() []IPMetric {
	// Pre-allocate with a reasonable estimate
	result := make([]IPMetric, 0, 1024)

	for i := range numShards {
		shard := bandwidthShards[i]
		shard.mu.RLock()
		for ip, s := range shard.m {
			result = append(result, IPMetric{
				IP:       ip,
				Requests: float64(atomic.LoadUint64(&s.requestCount)),
				BytesIn:  float64(atomic.LoadUint64(&s.bytesIn)),
				BytesOut: float64(atomic.LoadUint64(&s.bytesOut)),
			})
		}
		shard.mu.RUnlock()
	}
	return result
}

// evictIPBandwidthLocked removes about 25% of keys from the shard.
func evictIPBandwidthLocked(shard *bandwidthShard) {
	n := len(shard.m)
	if n == 0 {
		return
	}
	toEvict := (n / 4) + 1
	for k := range shard.m {
		delete(shard.m, k)
		toEvict--
		if toEvict <= 0 {
			break
		}
	}
}

// resetIPBandwidth clears all shards. Used for testing.
func resetIPBandwidth() {
	for i := range numShards {
		shard := bandwidthShards[i]
		shard.mu.Lock()
		shard.m = make(map[string]*ipBandwidthInternal)
		shard.mu.Unlock()
	}
}
