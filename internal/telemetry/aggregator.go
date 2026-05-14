package telemetry

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
)

// MetricPoint holds a single point in time for various metrics.
type MetricPoint struct {
	Timestamp  time.Time
	Requests   float64
	Errors     float64
	P99Latency float64
}

// IPStats holds per-IP metrics for a window.
type IPStats struct {
	mu         sync.Mutex
	LastUpdate time.Time
	Requests   float64
	AuthFail   float64
	WafBlocks  float64
}

// LocalMetricsAggregator collects and stores metrics in memory for anomaly detection.
type LocalMetricsAggregator struct {
	mu sync.RWMutex

	// Global short-term: 1-minute buckets for the last hour
	buckets []MetricPoint

	// IP tracking: Map of IP to a simple sliding window (last 5 minutes)
	ipStats *sync.Map // map[string]*IPStats

	maxBuckets int
	cachedQPS  atomic.Uint64
}

var (
	GlobalAggregator *LocalMetricsAggregator
	aggOnce          sync.Once
)

func GetAggregator() *LocalMetricsAggregator {
	aggOnce.Do(func() {
		GlobalAggregator = &LocalMetricsAggregator{
			buckets:    make([]MetricPoint, 0, 60),
			ipStats:    &sync.Map{},
			maxBuckets: 60,
		}
	})
	return GlobalAggregator
}

func (a *LocalMetricsAggregator) Start(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	pruneTicker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	defer pruneTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.takeSnapshot()
		case <-pruneTicker.C:
			a.pruneIPs()
		}
	}
}

func (a *LocalMetricsAggregator) takeSnapshot() {
	snap, err := CollectMetricsSnapshot(10, 0)
	if err != nil {
		logger.L.LogError("failed to collect metrics snapshot for aggregator", "error", err)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// 1. Golden Signals
	point := MetricPoint{
		Timestamp:  time.Now(),
		Requests:   snap.GoldenSignals.RequestsTotal,
		Errors:     snap.GoldenSignals.ErrorsTotal,
		P99Latency: snap.GoldenSignals.P99LatencyMs / 1000.0, // convert to seconds
	}

	a.buckets = append(a.buckets, point)
	if len(a.buckets) > a.maxBuckets {
		a.buckets = a.buckets[1:]
	}
	a.mu.Unlock()

	// Update cached QPS (approximate from last bucket)
	qps := a.GetRate("requests", 5*time.Minute)
	a.cachedQPS.Store(uint64(qps))
}

func (a *LocalMetricsAggregator) pruneIPs() {
	now := time.Now()
	a.ipStats.Range(func(key, value any) bool {
		s := value.(*IPStats)
		if now.Sub(s.LastUpdate) > 10*time.Minute {
			a.ipStats.Delete(key)
		}
		return true
	})
}

func (a *LocalMetricsAggregator) RecordRequest(ip string, status int) {
	s := a.getIPStats(ip)
	s.mu.Lock()
	s.Requests++
	s.LastUpdate = time.Now()
	if status == 401 || status == 403 {
		s.AuthFail++
	}
	s.mu.Unlock()
}

func (a *LocalMetricsAggregator) RecordWAFBlock(ip string) {
	s := a.getIPStats(ip)
	s.mu.Lock()
	s.WafBlocks++
	s.LastUpdate = time.Now()
	s.mu.Unlock()
}

func (a *LocalMetricsAggregator) getIPStats(ip string) *IPStats {
	if val, ok := a.ipStats.Load(ip); ok {
		return val.(*IPStats)
	}
	s := &IPStats{LastUpdate: time.Now()}
	actual, _ := a.ipStats.LoadOrStore(ip, s)
	return actual.(*IPStats)
}

type IPResult struct {
	IP        string
	Requests  float64
	AuthFail  float64
	WafBlocks float64
}

func (a *LocalMetricsAggregator) GetIPStats(minRequests float64) []IPResult {
	var results []IPResult
	a.ipStats.Range(func(key, value any) bool {
		s := value.(*IPStats)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.Requests >= minRequests || s.WafBlocks > 0 || s.AuthFail > 0 {
			results = append(results, IPResult{
				IP:        key.(string),
				Requests:  s.Requests,
				AuthFail:  s.AuthFail,
				WafBlocks: s.WafBlocks,
			})
		}
		return true
	})
	return results
}

// ResetIPStats clears the per-IP counters. Should be called by AnomalyDetector after each check interval.
func (a *LocalMetricsAggregator) ResetIPStats() {
	a.ipStats.Range(func(key, value any) bool {
		s := value.(*IPStats)
		s.mu.Lock()
		s.Requests = 0
		s.AuthFail = 0
		s.WafBlocks = 0
		s.mu.Unlock()
		return true
	})
}

// GetRate returns the rate of change for a metric over the last 'duration'.
func (a *LocalMetricsAggregator) GetRate(metric string, duration time.Duration) float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.buckets) < 2 {
		return 0
	}

	now := time.Now()
	startTime := now.Add(-duration)

	var startPoint, endPoint *MetricPoint
	for i := len(a.buckets) - 1; i >= 0; i-- {
		p := &a.buckets[i]
		if endPoint == nil {
			endPoint = p
		}
		if p.Timestamp.Before(startTime) {
			break
		}
		startPoint = p
	}

	if startPoint == nil || endPoint == nil || startPoint == endPoint {
		return 0
	}

	var startVal, endVal float64
	switch metric {
	case "requests":
		startVal, endVal = startPoint.Requests, endPoint.Requests
	case "errors":
		startVal, endVal = startPoint.Errors, endPoint.Errors
	default:
		return 0
	}

	diff := endVal - startVal
	if diff < 0 {
		diff = 0 // Counter reset
	}

	seconds := endPoint.Timestamp.Sub(startPoint.Timestamp).Seconds()
	if seconds <= 0 {
		return 0
	}

	return diff / seconds
}

func (a *LocalMetricsAggregator) GetP99Latency(duration time.Duration) float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.buckets) == 0 {
		return 0
	}

	startTime := time.Now().Add(-duration)
	var sum float64
	var count int
	for i := len(a.buckets) - 1; i >= 0; i-- {
		p := &a.buckets[i]
		if p.Timestamp.Before(startTime) {
			break
		}
		sum += p.P99Latency
		count++
	}

	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

func (a *LocalMetricsAggregator) GetCachedQPS() float64 {
	return float64(a.cachedQPS.Load())
}
