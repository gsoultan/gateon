// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Two properties a load number cannot tell you, and both are hardware
// independent: whether the gateway leaks under sustained traffic, and whether it
// drains cleanly when told to stop. A gateway that leaks falls over on day three
// rather than in a benchmark, and one that will not drain blocks every rolling
// deploy. Neither is visible in throughput.
//
// Opt-in: these build and run the real binary and take a minute or two.
//
//	GATEON_SOAK_TEST=1 go test ./tests/e2e/ -run 'TestSoak|TestGracefulDrain' -v -timeout 15m

const (
	soakConcurrency = 24
	soakDuration    = 45 * time.Second // override with GATEON_SOAK_SECONDS
)

// startGateon launches the real binary with pprof enabled and returns the
// process, its HTTPS port and the pprof port. The caller owns the lifecycle:
// nothing is auto-killed, because the drain test needs to send its own signal
// and watch the process exit on its own.
func startGateon(t *testing.T, projectRoot string, env *TestEnv) (cmd *exec.Cmd, httpsPort, pprofPort int) {
	t.Helper()
	binary := filepath.Join(env.Dir, "gateon"+exeSuffix())
	build := exec.Command("go", "build", "-o", binary, "./cmd/gateon")
	build.Dir = projectRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("failed to build gateon: %v\n%s", err, out)
	}

	pprofPort = getFreePort(t)
	cmd = exec.Command(binary)
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
		fmt.Sprintf("GATEON_PPROF_ADDR=127.0.0.1:%d", pprofPort),
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start gateon: %v", err)
	}
	waitForPort(t, env.Ports["http_tls"])
	return cmd, env.Ports["http_tls"], pprofPort
}

// goroutineCount reads the live goroutine total from pprof. The first line of
// the debug=1 goroutine profile is "goroutine profile: total N".
func goroutineCount(t *testing.T, pprofPort int) int {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/debug/pprof/goroutine?debug=1", pprofPort))
	if err != nil {
		t.Fatalf("pprof goroutine fetch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	sc := bufio.NewScanner(resp.Body)
	if sc.Scan() {
		fields := strings.Fields(sc.Text()) // "goroutine profile: total 42"
		if len(fields) >= 4 {
			if n, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
				return n
			}
		}
	}
	t.Fatalf("could not parse goroutine total")
	return 0
}

// rssKB reads the process resident set size via ps. Actual process memory is a
// more honest soak signal than a Go heap sample, which excludes the runtime's
// own retained pages.
func rssKB(pid int) int {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return -1
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

func soakClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- self-signed test cert
			MaxIdleConns:        soakConcurrency * 2,
			MaxIdleConnsPerHost: soakConcurrency * 2,
			MaxConnsPerHost:     soakConcurrency * 2,
		},
	}
}

// hammer drives requests as fast as it can until ctx is cancelled, returning the
// completed and failed counts. Bodies are drained so connections are reused.
func hammer(ctx context.Context, client *http.Client, url string, conc int) (done, failed int64) {
	var d, f atomic.Int64
	var wg sync.WaitGroup
	for range conc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				resp, err := client.Get(url)
				if err != nil {
					f.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					d.Add(1)
				} else {
					f.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	return d.Load(), f.Load()
}

func TestSoakStability(t *testing.T) {
	if os.Getenv("GATEON_SOAK_TEST") != "1" {
		t.Skip("soak test: set GATEON_SOAK_TEST=1 to run (builds and runs the binary)")
	}
	projectRoot, _ := filepath.Abs("../..")
	env := SetupTestEnv(t)
	mock := startMockBackend(t, projectRoot, env)
	defer func() { _ = mock.Process.Kill() }()

	cmd, httpsPort, pprofPort := startGateon(t, projectRoot, env)
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	pid := cmd.Process.Pid
	url := fmt.Sprintf("https://127.0.0.1:%d/test", httpsPort)
	client := soakClient()

	dur := soakDuration
	if s := os.Getenv("GATEON_SOAK_SECONDS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			dur = time.Duration(n) * time.Second
		}
	}

	// Warm up, then settle, so the baseline reflects steady idle state (pools
	// filled, WAF state built) rather than a cold process.
	{
		warmCtx, warmCancel := context.WithTimeout(context.Background(), 5*time.Second)
		hammer(warmCtx, client, url, soakConcurrency)
		warmCancel()
	}
	time.Sleep(2 * time.Second)
	baseGoroutines := goroutineCount(t, pprofPort)
	baseRSS := rssKB(pid)
	t.Logf("baseline (idle, post-warmup): goroutines=%d rss=%dMB", baseGoroutines, baseRSS/1024)

	// Sustained load, sampling as it runs.
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	var peakGoroutines, peakRSS int
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
				g := goroutineCount(t, pprofPort)
				r := rssKB(pid)
				if g > peakGoroutines {
					peakGoroutines = g
				}
				if r > peakRSS {
					peakRSS = r
				}
				t.Logf("  under load: goroutines=%d rss=%dMB", g, r/1024)
			}
		}
	}()
	done, failed := hammer(ctx, client, url, soakConcurrency)
	cancel()
	<-sampleDone
	t.Logf("sustained %s: %d ok, %d failed, peak goroutines=%d peak rss=%dMB",
		dur, done, failed, peakGoroutines, peakRSS/1024)

	if done == 0 {
		t.Fatal("no successful requests during soak; the run is meaningless")
	}
	if failed > done/100 {
		t.Errorf("%d/%d requests failed under sustained load (>1%%)", failed, done+failed)
	}

	// Cool down and let the runtime reclaim per-request goroutines, then compare
	// against baseline. A goroutine leaked per request or per connection is the
	// common kind and shows here as a count that does not come back down.
	time.Sleep(5 * time.Second)
	finalGoroutines := goroutineCount(t, pprofPort)
	finalRSS := rssKB(pid)
	t.Logf("cooled down: goroutines=%d rss=%dMB", finalGoroutines, finalRSS/1024)

	// Allowance is generous in absolute terms but still catches a leak, which
	// grows with request count and would be in the thousands after a soak.
	if finalGoroutines > baseGoroutines+40 {
		t.Errorf("goroutines did not return to baseline after load: base=%d final=%d (leak suspected)",
			baseGoroutines, finalGoroutines)
	}
	// RSS is reported, not gated: Go returns freed pages to the OS lazily, so a
	// higher post-soak RSS is expected and not itself a leak. The goroutine
	// check above is the hard signal.
	t.Logf("rss delta over soak: %+dMB (informational; Go frees pages lazily)",
		(finalRSS-baseRSS)/1024)
}

// TestGracefulDrain verifies the property every rolling deploy depends on: when
// the gateway is told to stop mid-traffic, it drains in-flight work and exits on
// its own within ShutdownTimeout, rather than hanging (blocking the rollout) or
// being force-killed (dropping live requests).
func TestGracefulDrain(t *testing.T) {
	if os.Getenv("GATEON_SOAK_TEST") != "1" {
		t.Skip("drain test: set GATEON_SOAK_TEST=1 to run (builds and runs the binary)")
	}
	projectRoot, _ := filepath.Abs("../..")
	env := SetupTestEnv(t)
	mock := startMockBackend(t, projectRoot, env)
	defer func() { _ = mock.Process.Kill() }()

	cmd, httpsPort, _ := startGateon(t, projectRoot, env)
	// Slow backend responses (2s) so these requests are genuinely mid-flight
	// through the proxy when the signal lands. 2s is well inside ShutdownTimeout
	// (30s), so a correct drain has ample budget to let them finish.
	const inFlight = 8
	url := fmt.Sprintf("https://127.0.0.1:%d/test?delay=2000", httpsPort)
	client := soakClient()

	type result struct {
		status int
		err    error
	}
	results := make(chan result, inFlight)
	for range inFlight {
		go func() {
			resp, err := client.Get(url)
			if err != nil {
				results <- result{err: err}
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			results <- result{status: resp.StatusCode}
		}()
	}

	// Let the requests reach the backend and block on its delay, so they are
	// unambiguously in-flight before the signal.
	time.Sleep(700 * time.Millisecond)

	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM: %v", err)
	}
	start := time.Now()

	const margin = 10 * time.Second
	select {
	case err := <-waitErr:
		elapsed := time.Since(start)
		t.Logf("drained and exited in %s (err=%v)", elapsed.Round(time.Millisecond), err)
		if elapsed > 30*time.Second+margin {
			t.Errorf("drain took %s, past ShutdownTimeout+margin", elapsed)
		}
	case <-time.After(30*time.Second + margin):
		_ = cmd.Process.Kill()
		t.Fatalf("gateway did not exit within ShutdownTimeout+margin after SIGTERM; drain hangs (would block a rollout)")
	}

	// The property that matters: every request already in flight when SIGTERM
	// arrived completed with 200. A drain that closes listeners but resets
	// established requests would show these as connection errors instead.
	ok, bad := 0, 0
	for range inFlight {
		r := <-results
		if r.err == nil && r.status == http.StatusOK {
			ok++
		} else {
			bad++
			t.Logf("  in-flight request not drained: status=%d err=%v", r.status, r.err)
		}
	}
	t.Logf("in-flight at SIGTERM: %d completed 200, %d dropped", ok, bad)
	if bad > 0 {
		t.Errorf("%d/%d in-flight requests were dropped on shutdown; a rolling deploy would 5xx", bad, inFlight)
	}
}
