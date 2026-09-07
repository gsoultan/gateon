// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Gateon's stated deployment target is a 2 core / 2 GB host. TestSoakStability
// proves the gateway does not leak, but it proves it on whatever machine runs
// it -- typically a laptop with eight or more cores and plenty of headroom. A
// process that is comfortable there can still thrash on the target, and the
// failure that matters on a small host is not a leak, it is the gateway
// competing with itself for two cores and a GC that never gets ahead.
//
// So this runs the same binary with the budget pinned: GOMAXPROCS at the core
// count, GATEON_MEMORY_LIMIT at the memory the runtime is allowed to use, and
// asserts the things that only go wrong when a machine is small -- resident
// memory staying inside the host, latency not collapsing, and the process still
// being alive at the end.
//
// What this is not: a cgroup. The Go runtime is held to the budget, and that is
// the part Gateon controls, but the kernel is not stopping this process from
// using more. It catches a gateway that wants more than the target has; it does
// not reproduce what the OOM killer does when it gets it. The load generator and
// the mock backend also run on the same machine and are not inside the budget,
// so the gateway gets two cores' worth of Go scheduling without the kernel
// network stack of a real two-core box competing for them. Read the numbers as
// the gateway's own appetite, not as a capacity figure for the target.
//
// Measured on 2026-09-07, 2 cores / 1536 MiB, 45s at concurrency 24:
//
//	479,317 requests, 0 failed, 10,651 req/s
//	p50 1.5ms  p90 4.8ms  p99 11.4ms  max 54.8ms
//	RSS 131MB baseline, 140MB peak, 121MB settled; goroutines 127 -> ~145
//
// The thresholds below are anchored to that run with room for slower hardware,
// not to the host budget alone -- a ceiling of 1740MB against an observed 140MB
// would let a twelvefold regression through and still pass.
//
//	GATEON_SOAK_TEST=1 go test ./tests/e2e/ -run TestSoakOnDeploymentBudget -v -timeout 15m

const (
	// The deployment target: see the Gateon deployment notes. Overridable so the
	// same test can be pointed at whatever a given install actually runs on.
	budgetCores      = 2
	budgetHostMiB    = 2048
	budgetRuntimeMiB = 1536 // what the Go runtime may use; the rest is the OS and headroom

	// Above this and the host has nothing left for the kernel, the mock backend
	// or anything else sharing the box. This is the "does it fit the target at
	// all" line.
	budgetRSSCeilingMiB = 1740 // 85% of the host

	// The regression line. Observed peak is ~140MB, so this allows roughly
	// three and a half times that before failing: enough that slower or busier
	// hardware does not trip it, tight enough that a structural change in what
	// the gateway retains is visible instead of disappearing into a budget it
	// was never close to.
	budgetRSSRegressionMiB = 512

	// Observed p99 is ~11ms. A second is two orders of magnitude of headroom and
	// still catches the failure this budget exists to surface: a tail that grows
	// because two cores cannot keep up, rather than because the work got harder.
	budgetP99Ceiling = 1 * time.Second

	budgetConcurrency = 24
	budgetDuration    = 60 * time.Second
)

// latencySample records one request's outcome.
type latencySample struct {
	d  time.Duration
	ok bool
}

// hammerTimed drives load like hammer, but keeps the latency of every request so
// the run can report percentiles rather than a throughput number.
//
// Percentiles are the point on a small host: mean latency hides exactly the
// behaviour a two-core box produces, which is most requests being fine and a
// tail that grows as the scheduler and the GC start contending.
func hammerTimed(ctx context.Context, client *http.Client, url string, conc int) []latencySample {
	var mu sync.Mutex
	all := make([]latencySample, 0, 8192)

	var wg sync.WaitGroup
	for range conc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]latencySample, 0, 1024)
			for ctx.Err() == nil {
				start := time.Now()
				resp, err := client.Get(url)
				if err != nil {
					local = append(local, latencySample{d: time.Since(start)})
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				local = append(local, latencySample{
					d:  time.Since(start),
					ok: resp.StatusCode == http.StatusOK,
				})
			}
			mu.Lock()
			all = append(all, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return all
}

// percentile returns the p-th percentile of the successful latencies.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * p)
	return sorted[i]
}

func TestSoakOnDeploymentBudget(t *testing.T) {
	if os.Getenv("GATEON_SOAK_TEST") != "1" {
		t.Skip("budget soak: set GATEON_SOAK_TEST=1 to run (builds and runs the binary)")
	}

	cores := budgetCores
	if v := os.Getenv("GATEON_BUDGET_CORES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cores = n
		}
	}
	runtimeMiB := budgetRuntimeMiB
	if v := os.Getenv("GATEON_BUDGET_RUNTIME_MIB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			runtimeMiB = n
		}
	}
	dur := budgetDuration
	if v := os.Getenv("GATEON_SOAK_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			dur = time.Duration(n) * time.Second
		}
	}

	projectRoot, _ := filepath.Abs("../..")
	env := SetupTestEnv(t)
	mock := startMockBackend(t, projectRoot, env)
	defer func() { _ = mock.Process.Kill() }()

	cmd, httpsPort, pprofPort := startGateon(t, projectRoot, env,
		fmt.Sprintf("GOMAXPROCS=%d", cores),
		fmt.Sprintf("GATEON_MEMORY_LIMIT=%dMiB", runtimeMiB),
	)
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	pid := cmd.Process.Pid

	t.Logf("budget: %d cores, %d MiB to the Go runtime, %d MiB host",
		cores, runtimeMiB, budgetHostMiB)

	url := fmt.Sprintf("https://127.0.0.1:%d/test", httpsPort)
	client := soakClient()

	// Warm up so the baseline is a settled process rather than a cold one:
	// pools filled, WAF state built, TLS sessions established.
	{
		warmCtx, warmCancel := context.WithTimeout(context.Background(), 5*time.Second)
		hammer(warmCtx, client, url, budgetConcurrency)
		warmCancel()
	}
	time.Sleep(2 * time.Second)
	baseRSS := rssKB(pid)
	baseGoroutines := goroutineCount(t, pprofPort)
	t.Logf("baseline (idle, post-warmup): rss=%dMB goroutines=%d", baseRSS/1024, baseGoroutines)

	// Sustained load with sampling.
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	// Seeded from the baseline so "peak" is a peak. Sampling only during load
	// meant a run whose GC returned pages reported a peak below its own
	// baseline, which reads as nonsense in the log and would understate a
	// regression that happened to land between ticks.
	peakRSS, peakGoroutines := baseRSS, baseGoroutines
	sampleDone := make(chan struct{})
	go func() {
		defer close(sampleDone)
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				r := rssKB(pid)
				g := goroutineCount(t, pprofPort)
				if r > peakRSS {
					peakRSS = r
				}
				if g > peakGoroutines {
					peakGoroutines = g
				}
				t.Logf("  under load: rss=%dMB goroutines=%d", r/1024, g)
			}
		}
	}()

	samples := hammerTimed(ctx, client, url, budgetConcurrency)
	cancel()
	<-sampleDone

	// The process must still be alive. On a host this small the interesting
	// failure is the gateway dying, not slowing down.
	if rssKB(pid) < 0 {
		t.Fatalf("the gateway is no longer running after %s at %d cores / %d MiB. "+
			"That is the failure this test exists for: it survives on a large "+
			"machine and does not survive on the one it ships to.",
			dur, cores, runtimeMiB)
	}

	var okCount int
	oks := make([]time.Duration, 0, len(samples))
	for _, s := range samples {
		if s.ok {
			okCount++
			oks = append(oks, s.d)
		}
	}
	sort.Slice(oks, func(i, j int) bool { return oks[i] < oks[j] })

	total := len(samples)
	if total == 0 {
		t.Fatal("no requests completed; the load generator never reached the gateway")
	}
	failRate := float64(total-okCount) / float64(total)
	rps := float64(okCount) / dur.Seconds()

	t.Logf("sustained %s at %d cores: %d ok / %d total (%.2f%% failed), %.0f req/s",
		dur, cores, okCount, total, failRate*100, rps)
	t.Logf("latency: p50=%v p90=%v p99=%v max=%v",
		percentile(oks, 0.50), percentile(oks, 0.90), percentile(oks, 0.99),
		percentile(oks, 1.0))
	t.Logf("memory: baseline=%dMB peak=%dMB ceiling=%dMB (host %dMB)",
		baseRSS/1024, peakRSS/1024, budgetRSSCeilingMiB, budgetHostMiB)

	// 1. Resident memory has to stay inside the host, with room for the kernel
	//    and anything else on the box. GATEON_MEMORY_LIMIT is a soft limit on
	//    the Go heap: exceeding this means the runtime could not hold the line,
	//    and on a real 2 GB host the OOM killer decides what happens next.
	if peakRSS/1024 > budgetRSSCeilingMiB {
		t.Errorf("peak RSS %dMB exceeds the %dMB ceiling on a %dMB host.\n"+
			"GATEON_MEMORY_LIMIT was set to %dMiB and the process went past it, so "+
			"the soft limit is not holding: on the target the kernel resolves this, "+
			"not the GC.", peakRSS/1024, budgetRSSCeilingMiB, budgetHostMiB, runtimeMiB)
	} else if peakRSS/1024 > budgetRSSRegressionMiB {
		// Not a capacity failure -- there is plenty of host left -- but the
		// gateway is holding several times what it used to, and on a 2 GB box
		// that headroom is the whole margin.
		t.Errorf("peak RSS %dMB is over the %dMB regression line (observed peak when "+
			"this was written: 140MB). It still fits the host, so nothing is broken "+
			"yet; something now retains far more per request than it did, and this "+
			"is where that is cheap to find.",
			peakRSS/1024, budgetRSSRegressionMiB)
	}

	// 2. Failures. A few connection resets at this concurrency are the load
	//    generator's, not the gateway's; a broad failure rate is the gateway
	//    refusing work it accepted.
	if failRate > 0.01 {
		t.Errorf("%.2f%% of requests failed under the deployment budget, want under 1%%. "+
			"At %d cores the gateway is dropping work it accepted.", failRate*100, cores)
	}

	// 3. The tail. A two-core host will not match a laptop, and it does not have
	//    to -- but a p99 in the seconds means requests are queueing behind the
	//    scheduler or a GC that cannot keep up, which is what this budget is
	//    meant to surface.
	if p99 := percentile(oks, 0.99); p99 > budgetP99Ceiling {
		t.Errorf("p99 latency %v under the deployment budget, want under %v "+
			"(observed when this was written: 11.4ms). Most requests are fine and "+
			"the tail is not; on %d cores that is contention, not load.",
			p99, budgetP99Ceiling, cores)
	}

	// 4. Leak signals, same as the unconstrained soak but under pressure, where
	//    a retained allocation costs proportionally far more.
	if baseGoroutines > 0 && peakGoroutines > baseGoroutines*4 {
		t.Errorf("goroutines grew from %d to %d under load; on a small host an "+
			"unbounded goroutine population is a memory problem before it is a "+
			"scheduling one", baseGoroutines, peakGoroutines)
	}

	// 5. Settle. After the load stops, memory should come back down: what is
	//    still held once traffic ends is what a long-lived process accumulates.
	time.Sleep(5 * time.Second)
	settledRSS := rssKB(pid)
	t.Logf("settled (5s after load): rss=%dMB", settledRSS/1024)
	if baseRSS > 0 && settledRSS > baseRSS*3 {
		t.Errorf("resident memory settled at %dMB against a %dMB baseline. Traffic "+
			"has stopped, so this is retained rather than in use, and on a %dMB "+
			"host each restart-to-restart increment matters.",
			settledRSS/1024, baseRSS/1024, budgetHostMiB)
	}
}
