// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
)

// RunningStats implements Welford's Online Algorithm for computing running
// mean and variance with high numerical stability and O(1) space/time.
type RunningStats struct {
	Count int64
	Mean  float64
	M2    float64
}

func (s *RunningStats) Update(x float64) {
	s.Count++
	delta := x - s.Mean
	s.Mean += delta / float64(s.Count)
	delta2 := x - s.Mean
	s.M2 += delta * delta2
}

func (s *RunningStats) Variance() float64 {
	if s.Count < 2 {
		return 0
	}
	return s.M2 / float64(s.Count-1)
}

func (s *RunningStats) StdDev() float64 {
	return math.Sqrt(s.Variance())
}

func (s *RunningStats) ZScore(x float64) float64 {
	std := s.StdDev()
	if std <= 0.0001 { // Avoid division by zero and noisy tiny stddevs
		return 0
	}
	return (x - s.Mean) / std
}

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
	// AuthFail counts refused credential attempts (credentialRefusal), not
	// every 401 and 403: the brute-force check reads it.
	AuthFail  float64
	WafBlocks float64
}

// maxAggregatorIPs bounds the per-IP anomaly window. It is keyed by the client
// address, which is the attacker's to choose -- an IPv6 /64 alone holds 2^64 of
// them -- and used to grow by one entry per distinct address for the ten
// minutes pruneIPs waits before dropping an idle one. When it is full, about a
// quarter of the entries are dropped, the bulk policy the bandwidth tracker in
// ipstats.go and the path map in stats.go already use.
const maxAggregatorIPs = 10000

// LocalMetricsAggregator collects and stores metrics in memory for anomaly detection.
type LocalMetricsAggregator struct {
	mu sync.RWMutex

	// Global short-term: 1-minute buckets for the last hour
	buckets []MetricPoint

	// IP tracking: Map of IP to a simple sliding window (last 5 minutes)
	ipStats *sync.Map // map[string]*IPStats
	// ipCount is how many addresses ipStats holds, since sync.Map has no
	// length; evictMu lets one goroutine at a time do the bulk eviction.
	ipCount atomic.Int64
	evictMu sync.Mutex

	maxBuckets int
	cachedQPS  atomic.Uint64

	// Advanced Stats for Z-Score anomaly detection
	StatsRequests *RunningStats
	StatsLatency  *RunningStats
}

var (
	GlobalAggregator *LocalMetricsAggregator
	aggOnce          sync.Once
)

func GetAggregator() *LocalMetricsAggregator {
	aggOnce.Do(func() {
		GlobalAggregator = &LocalMetricsAggregator{
			buckets:       make([]MetricPoint, 0, 60),
			ipStats:       &sync.Map{},
			maxBuckets:    60,
			StatsRequests: &RunningStats{},
			StatsLatency:  &RunningStats{},
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
			a.takeSnapshot(ctx)
		case <-pruneTicker.C:
			a.pruneIPs()
		}
	}
}

func (a *LocalMetricsAggregator) takeSnapshot(ctx context.Context) {
	// Use limit=50 to hit the background-refreshed snapshot cache.
	snap, err := CollectMetricsSnapshot(ctx, 50, 0)
	if err != nil {
		logger.L.LogError("failed to collect metrics snapshot for aggregator", "error", err)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Update running stats for Z-Score anomaly detection. The error-rate
	// baseline is read from the buckets instead; see errorZScore.
	a.StatsRequests.Update(snap.GoldenSignals.RequestsTotal)
	a.StatsLatency.Update(snap.GoldenSignals.P99LatencyMs / 1000.0)

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

	// Update cached QPS (approximate from last bucket)
	qps := a.GetRateLocked("requests", 5*time.Minute)
	a.cachedQPS.Store(uint64(qps))
}

// errorRateFloor is the least spread the error-rate baseline is taken to have:
// one error a minute, the resolution of a minute's sample. A service with no
// 5xx all hour has no spread at all, and without a floor its first outage would
// score either zero deviations or infinitely many.
const errorRateFloor = 1.0 / 60

// errorZScore scores x, a 5xx rate in errors per second over the last window,
// against the per-minute rates of the hour the buckets hold before that window.
//
// It used to score x against running statistics fed the cumulative 5xx
// counter -- a count, not a rate -- so after an hour at a few errors a minute
// the "baseline" mean was in the hundreds and an outage at 8/s scored below
// it: no error spike could ever be reported. Read under the lock takeSnapshot
// appends buckets under.
func (a *LocalMetricsAggregator) errorZScore(x float64, window time.Duration) float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	baseline := a.errorRateBaselineLocked(time.Now().Add(-window))
	if baseline.Count < 2 {
		return 0
	}
	return (x - baseline.Mean) / max(baseline.StdDev(), errorRateFloor)
}

// errorRateBaselineLocked returns the statistics of the 5xx rate, in errors per
// second, over each interval between consecutive buckets that ends by cutoff.
func (a *LocalMetricsAggregator) errorRateBaselineLocked(cutoff time.Time) RunningStats {
	var s RunningStats
	for i := 1; i < len(a.buckets); i++ {
		prev, cur := a.buckets[i-1], a.buckets[i]
		if cur.Timestamp.After(cutoff) {
			break
		}
		secs := cur.Timestamp.Sub(prev.Timestamp).Seconds()
		if secs <= 0 {
			continue
		}
		s.Update(max(0, cur.Errors-prev.Errors) / secs) // a drop is a counter reset
	}
	return s
}

// latencyZScore scores x against the running statistics under the lock
// takeSnapshot updates them under. The anomaly detector calls it from its own
// goroutine, and a score is only meaningful if Count, Mean and M2 are read as
// one set -- read without the lock, they could come from two different updates.
func (a *LocalMetricsAggregator) latencyZScore(x float64) float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.StatsLatency.ZScore(x)
}

func (a *LocalMetricsAggregator) pruneIPs() {
	now := time.Now()
	a.ipStats.Range(func(key, value any) bool {
		s := value.(*IPStats)
		// LastUpdate is written under the entry's own lock by RecordRequest and
		// RecordWAFBlock, both on the request path, so it has to be read under
		// it too: this loop ran every five minutes against live traffic and the
		// race detector reports the pair.
		s.mu.Lock()
		idle := now.Sub(s.LastUpdate)
		s.mu.Unlock()
		if idle > 10*time.Minute {
			a.deleteIP(key)
		}
		return true
	})
}

// RecordRequest counts one finished request from ip, answered status. r is the
// request, read only when the answer was a refusal (credentialRefusal).
func (a *LocalMetricsAggregator) RecordRequest(ip string, status int, r *http.Request) {
	refused := credentialRefusal(status, r)
	s := a.getIPStats(ip)
	s.mu.Lock()
	s.Requests++
	s.LastUpdate = time.Now()
	if refused {
		s.AuthFail++
	}
	s.mu.Unlock()
}

// credentialRefusal reports whether a finished request was a credential
// attempt the server refused: answered 401 or 403, and either a POST -- how a
// login form or a token request submits one -- or carrying a password in its
// Authorization header, which is how HTTP Basic and Digest are guessed over
// GET. The per-IP threat detector judges its traces by the same rule, and the
// traces' passwordAuth flag is presentsPassword too, so the two detectors agree
// on what an attempt is.
//
// Any other refusal is not a guess: a tab polling after its session expired, a
// client re-presenting a stale bearer token, a scanner the WAF refused (which
// the exploit check reads from WafBlocks). Counting those shunned the expired
// tab. Nor is a refusal the gateway marked as its own (request.Refused): a POST
// whose token the gateway's own verification refused is a Connect, gRPC-Web or
// GraphQL poller whose session ended, not a password guess (ADR 0031). The
// mark is written by the middleware that refused, never read off the request,
// so a stuffing POST to a login form that adds a bearer header still counts.
// Nor is any other refusal the gateway wrote before the request reached its
// service -- a geofence, a WAF, a trap, bot management, deception, TLS
// binding -- unless its authentication marked it: none of them checked a
// credential (request.RequestState.CredentialChecked, ADR 0059). Read only
// for a 401 or 403, from the method, the header's scheme and the request
// state, allocating nothing.
func credentialRefusal(status int, r *http.Request) bool {
	if (status != http.StatusUnauthorized && status != http.StatusForbidden) || r == nil {
		return false
	}
	if rs := request.GetRequestState(r); rs != nil && !rs.CredentialChecked() {
		return false
	}
	return r.Method == http.MethodPost || presentsPassword(r.Header)
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
	if a.ipCount.Load() >= maxAggregatorIPs {
		a.evictIPStats()
	}
	s := &IPStats{LastUpdate: time.Now()}
	actual, loaded := a.ipStats.LoadOrStore(ip, s)
	if !loaded {
		a.ipCount.Add(1)
	}
	return actual.(*IPStats)
}

// evictIPStats drops about a quarter of the tracked addresses so new ones can
// be admitted. One goroutine evicts at a time; the others carry on and insert,
// so under contention the bound is overshot by at most the number of
// concurrent inserters rather than the request path queueing behind the
// eviction.
func (a *LocalMetricsAggregator) evictIPStats() {
	if !a.evictMu.TryLock() {
		return
	}
	defer a.evictMu.Unlock()
	toEvict := maxAggregatorIPs / 4
	a.ipStats.Range(func(key, _ any) bool {
		a.deleteIP(key)
		toEvict--
		return toEvict > 0
	})
}

// deleteIP removes an address and keeps ipCount exact when the prune loop and
// an eviction race to remove the same key.
func (a *LocalMetricsAggregator) deleteIP(key any) {
	if _, loaded := a.ipStats.LoadAndDelete(key); loaded {
		a.ipCount.Add(-1)
	}
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
	return a.GetRateLocked(metric, duration)
}

func (a *LocalMetricsAggregator) GetRateLocked(metric string, duration time.Duration) float64 {
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
