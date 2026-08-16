// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// PGO is applied to the built binary, so no package benchmark can measure it:
// `go test -bench` compiles the package under test, not ./cmd/gateon. That left
// "PGO is enabled" as a claim with nothing behind it — the profile was committed
// and verified to be applied, but its effect was never once observed.
//
// This drives real traffic through the real binary, twice: once as `make build`
// produces it (PGO auto-applied from cmd/gateon/default.pgo) and once built with
// -pgo=off. Everything else is held identical — same config, same ports, same
// mock backend, same load pattern, run back to back on the same machine.
//
// Not run by default. It takes minutes, it saturates the machine, and its
// numbers are only meaningful when nothing else is competing:
//
//	GATEON_LOAD_TEST=1 go test ./tests/e2e/ -run TestPGOImpact -v -timeout 30m
//
// Read the result with the loopback in mind. The mock backend, the load
// generator and the gateway all share one host, so a slice of every measurement
// is other people's work. That compresses the apparent delta — it does not
// invent one — so treat a positive result as a floor and a null result as
// "not resolvable here", not as "PGO does nothing".

type loadResult struct {
	label       string
	requests    int
	errors      int
	elapsed     time.Duration
	rps         float64
	p50, p90    time.Duration
	p99, maxLat time.Duration
}

func (r loadResult) String() string {
	return fmt.Sprintf("%-10s %8.0f req/s  p50=%-8s p90=%-8s p99=%-8s max=%-8s errors=%d",
		r.label, r.rps, r.p50.Round(time.Microsecond), r.p90.Round(time.Microsecond),
		r.p99.Round(time.Microsecond), r.maxLat.Round(time.Microsecond), r.errors)
}

const (
	loadConcurrency = 32
	loadRequests    = 20000
	loadWarmup      = 2000
	loadRounds      = 5
)

func TestPGOImpact(t *testing.T) {
	if os.Getenv("GATEON_LOAD_TEST") != "1" {
		t.Skip("load test: set GATEON_LOAD_TEST=1 to run (takes minutes, needs a quiet machine)")
	}

	projectRoot, _ := filepath.Abs("../..")
	env := SetupTestEnv(t) // builds ./cmd/gateon with PGO auto-applied

	// The comparison binary: same source, same flags, PGO explicitly disabled.
	noPGOPath := filepath.Join(env.Dir, "gateon_nopgo"+exeSuffix())
	build := exec.Command("go", "build", "-pgo=off", "-o", noPGOPath, "./cmd/gateon")
	build.Dir = projectRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("failed to build the -pgo=off binary: %v\n%s", err, out)
	}

	// Confirm the two binaries really differ in the way claimed, so a null
	// result cannot be "both runs were the same build".
	assertPGOApplied(t, env.BinaryPath, true)
	assertPGOApplied(t, noPGOPath, false)

	mock := startMockBackend(t, projectRoot, env)
	defer func() { _ = mock.Process.Kill() }()

	// Several rounds, alternating which binary goes first.
	//
	// One run each is an anecdote: a 1-2% difference is comfortably inside
	// run-to-run variance on a loopback, so a single pair cannot tell a real
	// effect from drift. Worse, running the same binary first every time makes
	// any warming or thermal trend a systematic bias in one direction — it would
	// show up as a consistent, entirely fake, win.
	//
	// Alternating cancels the order effect, and reporting every round rather
	// than only the mean lets a reader see the spread and judge whether the
	// direction is stable or whether the rounds simply disagree.
	var pgoRuns, nopgoRuns []loadResult
	for round := range loadRounds {
		if round%2 == 0 {
			pgoRuns = append(pgoRuns, runLoadAgainst(t, projectRoot, env, env.BinaryPath, "pgo"))
			nopgoRuns = append(nopgoRuns, runLoadAgainst(t, projectRoot, env, noPGOPath, "no-pgo"))
		} else {
			nopgoRuns = append(nopgoRuns, runLoadAgainst(t, projectRoot, env, noPGOPath, "no-pgo"))
			pgoRuns = append(pgoRuns, runLoadAgainst(t, projectRoot, env, env.BinaryPath, "pgo"))
		}
		t.Logf("  round %d/%d done", round+1, loadRounds)
	}

	t.Log("")
	for i := range loadRounds {
		t.Logf("  round %d  %s", i+1, nopgoRuns[i])
		t.Logf("  round %d  %s", i+1, pgoRuns[i])
	}
	t.Log("")

	nopgoRPS, nopgoSpread := medianRPS(nopgoRuns)
	pgoRPS, pgoSpread := medianRPS(pgoRuns)
	t.Logf("  median  no-pgo %8.0f req/s (spread %.1f%%)", nopgoRPS, nopgoSpread)
	t.Logf("  median  pgo    %8.0f req/s (spread %.1f%%)", pgoRPS, pgoSpread)

	if nopgoRPS > 0 {
		delta := (pgoRPS - nopgoRPS) / nopgoRPS * 100
		noise := max(nopgoSpread, pgoSpread)
		t.Logf("  median throughput %+.2f%%", delta)
		// The comparison that matters: is the effect bigger than the variance
		// the measurement itself shows? If not, this machine cannot resolve it,
		// which is a fact about the harness rather than about PGO.
		if abs(delta) < noise {
			t.Logf("  VERDICT: not resolvable here — the %+.2f%% difference is smaller than the "+
				"%.1f%% spread within a single binary's own rounds", delta, noise)
		} else {
			t.Logf("  VERDICT: %+.2f%% exceeds the %.1f%% within-binary spread", delta, noise)
		}
	}

	pgo, nopgo := pgoRuns[0], nopgoRuns[0]

	// Deliberately no threshold assertion. A pass/fail bound on a wall-clock
	// measurement taken on whatever machine happens to run it produces a flaky
	// test, and a flaky perf gate gets muted, which is worse than no gate. The
	// job here is to produce the number; judging it is a person's.
	if pgo.errors > 0 || nopgo.errors > 0 {
		t.Errorf("requests failed during the run (pgo=%d, no-pgo=%d); the numbers above are not trustworthy",
			pgo.errors, nopgo.errors)
	}
}

// medianRPS returns the median throughput and the spread (max-min as a percent
// of the median) across a binary's own rounds. The spread is the measurement's
// own noise floor: any difference between binaries smaller than it is not
// something this setup can resolve.
func medianRPS(runs []loadResult) (median, spreadPct float64) {
	if len(runs) == 0 {
		return 0, 0
	}
	vals := make([]float64, len(runs))
	for i, r := range runs {
		vals[i] = r.rps
	}
	sort.Float64s(vals)
	median = vals[len(vals)/2]
	if median > 0 {
		spreadPct = (vals[len(vals)-1] - vals[0]) / median * 100
	}
	return median, spreadPct
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// assertPGOApplied reads the build info rather than trusting the flag we passed.
func assertPGOApplied(t *testing.T, binary string, want bool) {
	t.Helper()
	out, err := exec.Command("go", "version", "-m", binary).CombinedOutput()
	if err != nil {
		t.Fatalf("go version -m %s: %v", binary, err)
	}
	// The setting is recorded as `build -pgo=<path>`; -pgo=off records "off".
	applied := false
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "-pgo=") {
			continue
		}
		applied = !strings.Contains(line, "-pgo=off")
	}
	if applied != want {
		t.Fatalf("%s: PGO applied = %v, want %v\n%s", filepath.Base(binary), applied, want, out)
	}
}

func startMockBackend(t *testing.T, projectRoot string, env *TestEnv) *exec.Cmd {
	t.Helper()
	mockPath := filepath.Join(env.Dir, "mock_backend"+exeSuffix())
	build := exec.Command("go", "build", "-o", mockPath, "tests/e2e/mock_backend/main.go")
	build.Dir = projectRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("failed to build mock backend: %v\n%s", err, out)
	}

	mock := exec.Command(mockPath)
	mock.Dir = projectRoot
	mock.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", env.Ports["mock_backend"]))
	if err := mock.Start(); err != nil {
		t.Fatalf("failed to start mock backend: %v", err)
	}
	waitForPort(t, env.Ports["mock_backend"])
	return mock
}

// runLoadAgainst starts one gateon binary, drives load through it and stops it.
// The two variants run sequentially on the same ports, so the previous process
// must be gone before the next binds.
func runLoadAgainst(t *testing.T, projectRoot string, env *TestEnv, binary, label string) loadResult {
	t.Helper()

	cmd := exec.Command(binary)
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GLOBAL_CONFIG_FILE=%s", filepath.Join(env.Dir, "config/global.json")),
		fmt.Sprintf("ROUTES_FILE=%s", filepath.Join(env.Dir, "config/routes.json")),
		fmt.Sprintf("SERVICES_FILE=%s", filepath.Join(env.Dir, "config/services.json")),
		fmt.Sprintf("ENTRYPOINTS_FILE=%s", filepath.Join(env.Dir, "config/entrypoints.json")),
		fmt.Sprintf("MIDDLEWARES_FILE=%s", filepath.Join(env.Dir, "config/middlewares.json")),
		fmt.Sprintf("TLS_OPTIONS_FILE=%s", filepath.Join(env.Dir, "config/tls_options.json")),
		"GATEON_TRUSTED_PROXIES=127.0.0.1,::1",
		"GATEON_TEST=1",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("%s: failed to start gateon: %v", label, err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		waitForPortRelease(t, env.Ports["http_tls"])
	}()

	waitForPort(t, env.Ports["http_tls"])

	url := fmt.Sprintf("https://127.0.0.1:%d/test", env.Ports["http_tls"])
	client := loadClient()

	// Warm up: the first requests pay for TLS handshakes, connection pool fill,
	// route-chain construction and lazily built WAF state, none of which is what
	// this is trying to measure.
	drive(client, url, loadWarmup, loadConcurrency)

	return drive(client, url, loadRequests, loadConcurrency).named(label)
}

func loadClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- self-signed test cert
			MaxIdleConns:        loadConcurrency * 2,
			MaxIdleConnsPerHost: loadConcurrency * 2,
			MaxConnsPerHost:     loadConcurrency * 2,
			DisableCompression:  true,
		},
	}
}

func (r loadResult) named(label string) loadResult { r.label = label; return r }

// drive issues n requests across c goroutines and summarises the latencies.
func drive(client *http.Client, url string, n, c int) loadResult {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		lats     = make([]time.Duration, 0, n)
		errCount int
	)

	perWorker := n / c
	start := time.Now()
	for range c {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]time.Duration, 0, perWorker)
			localErrs := 0
			for range perWorker {
				t0 := time.Now()
				resp, err := client.Get(url)
				if err != nil {
					localErrs++
					continue
				}
				// Draining is required for the connection to be reused; without
				// it every request pays a fresh handshake and the run measures
				// TLS, not the gateway.
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					localErrs++
					continue
				}
				local = append(local, time.Since(t0))
			}
			mu.Lock()
			lats = append(lats, local...)
			errCount += localErrs
			mu.Unlock()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	res := loadResult{
		requests: len(lats),
		errors:   errCount,
		elapsed:  elapsed,
	}
	if elapsed > 0 {
		res.rps = float64(len(lats)) / elapsed.Seconds()
	}
	if len(lats) > 0 {
		res.p50 = lats[len(lats)*50/100]
		res.p90 = lats[len(lats)*90/100]
		res.p99 = lats[min(len(lats)*99/100, len(lats)-1)]
		res.maxLat = lats[len(lats)-1]
	}
	return res
}
