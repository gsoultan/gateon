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
const maxIPBandwidthMapSize = 1024

var (
	ipBandwidthMap = make(map[string]*ipBandwidthInternal)
	ipBandwidthMu  sync.RWMutex
)

type ipBandwidthInternal struct {
	requestCount uint64
	bytesIn      uint64
	bytesOut     uint64
}

// RecordIPBandwidth accumulates cumulative request/byte counts for a client IP.
// It is bounded (maxIPBandwidthMapSize) and survives the anomaly detector's
// ResetIPStats cycle, so it can back the dashboard "Bandwidth by IP" card. It is
// safe for concurrent use and never blocks the hot path on the slow path beyond
// a brief write lock during first-insert/eviction.
func RecordIPBandwidth(ip string, bytesIn, bytesOut uint64) {
	if ip == "" {
		return
	}

	ipBandwidthMu.RLock()
	s, ok := ipBandwidthMap[ip]
	ipBandwidthMu.RUnlock()

	if !ok {
		ipBandwidthMu.Lock()
		s, ok = ipBandwidthMap[ip]
		if !ok {
			if len(ipBandwidthMap) >= maxIPBandwidthMapSize {
				evictIPBandwidthLocked()
			}
			s = &ipBandwidthInternal{}
			ipBandwidthMap[ip] = s
		}
		ipBandwidthMu.Unlock()
	}

	atomic.AddUint64(&s.requestCount, 1)
	atomic.AddUint64(&s.bytesIn, bytesIn)
	atomic.AddUint64(&s.bytesOut, bytesOut)
}

// getIPBandwidthStats returns a snapshot of the per-IP bandwidth tracker as
// IPMetric values for the metrics snapshot. Results are unsorted; the caller
// applies the same sort/top-N as the Prometheus-backed path.
func getIPBandwidthStats() []IPMetric {
	ipBandwidthMu.RLock()
	defer ipBandwidthMu.RUnlock()

	result := make([]IPMetric, 0, len(ipBandwidthMap))
	for ip, s := range ipBandwidthMap {
		result = append(result, IPMetric{
			IP:       ip,
			Requests: float64(atomic.LoadUint64(&s.requestCount)),
			BytesIn:  float64(atomic.LoadUint64(&s.bytesIn)),
			BytesOut: float64(atomic.LoadUint64(&s.bytesOut)),
		})
	}
	return result
}

// evictIPBandwidthLocked removes about 25% of keys from ipBandwidthMap.
// Must be called with ipBandwidthMu held for writing.
func evictIPBandwidthLocked() {
	n := len(ipBandwidthMap)
	if n == 0 {
		return
	}
	toEvict := (n / 4) + 1
	if toEvict > n {
		toEvict = n
	}
	for k := range ipBandwidthMap {
		delete(ipBandwidthMap, k)
		toEvict--
		if toEvict <= 0 {
			break
		}
	}
}
