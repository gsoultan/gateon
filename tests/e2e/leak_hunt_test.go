// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TestHostileInputUnderLoad covers what a hostile client puts *in* a request.
// This spec covers what a hostile client does *with a connection*: it opens
// one and says nothing, it upgrades and goes quiet, it upgrades to a backend
// that never answers, it resets HTTP/2 streams as fast as it can open them, it
// drips a chunked body forever, and it arrives from a different address every
// time. Each of these holds something in the gateway -- a goroutine, a socket,
// a map entry -- for as long as the gateway lets it, and the question is only
// whether the gateway lets go. It is measured the same way for every case: the
// goroutine count and the live heap, once the gateway has had time to settle,
// against the count before the case ran. A case that leaves goroutines behind
// also prints the stacks that grew, so the leak is named rather than counted.
//
// Opt-in, because it builds and runs the real binary for a few minutes:
//
//	GATEON_LEAK_TEST=1 go test ./tests/e2e/ -run TestConnectionsAreLetGo -v -timeout 20m
func TestConnectionsAreLetGo(t *testing.T) {
	if os.Getenv("GATEON_LEAK_TEST") != "1" {
		t.Skip("connection leak hunt: set GATEON_LEAK_TEST=1 to run")
	}
	projectRoot, _ := filepath.Abs("../..")
	env := SetupTestEnv(t)
	mock := startMockBackend(t, projectRoot, env)
	defer func() { _ = mock.Process.Kill() }()

	// A backend that accepts and never says a word, so an upgrade to it waits
	// on the gateway's bound and nothing else. One for HTTP and the tcp route.
	sink := silentListener(t)
	addSinkRoute(t, env, sink.Addr().String())

	logPath := filepath.Join(env.Dir, "gateon.log")
	cmd, tlsPort, pprofPort := startGateonLogged(t, projectRoot, env, logPath,
		"GOMAXPROCS=2", "GATEON_MEMORY_LIMIT=1536MiB", "GATEON_TRUSTED_PROXIES=127.0.0.1/32",
		// Short stream bounds, so a tunnel nobody uses is let go inside the
		// test rather than inside the tier's two minutes.
		"GATEON_STREAM_IDLE_TIMEOUT=5s", "GATEON_STREAM_MAX_LIFETIME=30s")
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	waitForPort(t, env.Ports["http_plain"])
	waitForPort(t, env.Ports["tcp"])

	tlsAddr := fmt.Sprintf("127.0.0.1:%d", tlsPort)
	plainAddr := fmt.Sprintf("127.0.0.1:%d", env.Ports["http_plain"])
	tcpAddr := fmt.Sprintf("127.0.0.1:%d", env.Ports["tcp"])
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- self-signed test cert
			MaxIdleConnsPerHost: 16,
		},
	}
	probe := func() int {
		req, _ := http.NewRequest(http.MethodGet, "https://"+tlsAddr+"/test/health", nil)
		req.Header.Set("X-Forwarded-For", "81.200.1.1")
		return fpDo(client, req)
	}
	if st := probe(); st != http.StatusOK {
		t.Fatalf("probe before the run: %d", st)
	}

	cases := []struct {
		name   string
		run    func(t *testing.T)
		settle time.Duration
	}{
		{"idle websocket tunnels", func(t *testing.T) {
			holdUpgrades(t, tlsAddr, "/synology/ws", 150, 12*time.Second)
		}, 10 * time.Second},
		{"upgrades to a silent backend", func(t *testing.T) {
			holdUpgrades(t, tlsAddr, "/sink/ws", 150, 20*time.Second)
		}, 15 * time.Second},
		{"upgrades the backend declines", func(t *testing.T) {
			holdUpgrades(t, tlsAddr, "/synology/not-a-socket", 150, 5*time.Second)
		}, 10 * time.Second},
		{"silent clients on the plain http entrypoint", func(t *testing.T) {
			holdSilent(t, plainAddr, nil, 300, 14*time.Second)
		}, 10 * time.Second},
		{"silent clients on the tls entrypoint", func(t *testing.T) {
			holdSilent(t, tlsAddr, &tls.Config{InsecureSkipVerify: true}, 300, 14*time.Second) // #nosec G402
		}, 10 * time.Second},
		{"silent clients on the tcp entrypoint", func(t *testing.T) {
			holdSilent(t, tcpAddr, nil, 300, 20*time.Second)
		}, 10 * time.Second},
		{"h2 rapid reset", func(t *testing.T) {
			rapidReset(t, tlsAddr, 32, 5000)
		}, 10 * time.Second},
		{"chunked bodies that never end", func(t *testing.T) {
			dripChunked(t, tlsAddr, "/test/api", 100, 25*time.Second)
		}, 10 * time.Second},
		{"a new address on every request", func(t *testing.T) {
			addressFlood(t, client, "https://"+tlsAddr, 30000)
		}, 10 * time.Second},
	}

	client.CloseIdleConnections()
	time.Sleep(3 * time.Second)
	baseG, baseStacks := goroutineProfile(t, pprofPort)
	// The copied config's routes plus the sink route added above; every one
	// is built on its first request or by the periodic pre-warm.
	const routesWithHandlers = 8
	baseHeap := heapInUseMiB(t, pprofPort)
	t.Logf("baseline: goroutines=%d heap_inuse=%dMiB rss=%dMB", baseG, baseHeap, rssKB(cmd.Process.Pid)/1024)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			startG, _ := goroutineProfile(t, pprofPort)
			c.run(t)
			if st := probe(); st != http.StatusOK {
				t.Errorf("benign probe right after the case: %d", st)
			}
			client.CloseIdleConnections()
			// Settle, but not longer than it takes: poll until the count stops
			// moving, then compare.
			endG, stacks := settledGoroutines(t, pprofPort, c.settle)
			heap := heapInUseMiB(t, pprofPort)
			t.Logf("goroutines %d -> %d (baseline %d), heap_inuse %dMiB (baseline %dMiB), rss %dMB",
				startG, endG, baseG, heap, baseHeap, rssKB(cmd.Process.Pid)/1024)
			if endG > baseG+40 {
				t.Errorf("goroutines did not come back down: %d -> %d", baseG, endG)
				for _, line := range grownStacks(baseStacks, stacks, 5) {
					t.Log(line)
				}
			}
			if heap > baseHeap+256 {
				t.Errorf("live heap grew by %dMiB and stayed there", heap-baseHeap)
			}
			// One health-check loop per route with a built handler, and never
			// more: a second loop for the same route is a handler that was
			// replaced and not closed. Handlers drain for up to 30s before
			// they close, so this is asked once that has passed.
			if loops := healthCheckLoops(stacks); loops > routesWithHandlers {
				time.Sleep(35 * time.Second)
				_, late := goroutineProfile(t, pprofPort)
				if loops = healthCheckLoops(late); loops > routesWithHandlers {
					t.Errorf("%d health-check loops for %d routes: a replaced proxy handler was not closed", loops, routesWithHandlers)
				}
			}
		})
	}

	logs, _ := os.ReadFile(logPath) // #nosec G304 -- the test's own temp dir
	for _, line := range bytes.Split(logs, []byte("\n")) {
		l := strings.ToLower(string(line))
		if strings.Contains(l, "panic") || strings.Contains(l, "fatal error") || strings.Contains(l, "data race") {
			t.Errorf("gateway log: %s", line)
		}
	}
}

// silentListener accepts every connection and never writes or closes it until
// the test ends.
func silentListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})
	return l
}

// addSinkRoute adds a service at addr and a /sink route to the copied config,
// before the gateway reads it.
func addSinkRoute(t *testing.T, env *TestEnv, addr string) {
	t.Helper()
	patch := func(name, needle, insert string) {
		p := filepath.Join(env.Dir, "config", name)
		b, err := os.ReadFile(p) // #nosec G304 -- the test's own temp dir
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		i := strings.LastIndex(s, needle)
		if i < 0 {
			t.Fatalf("%s: no %q to patch", name, needle)
		}
		s = s[:i] + insert + s[i:]
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	patch("services.json", "]", fmt.Sprintf(`,{"id":"sink-service","name":"Sink","weighted_targets":[{"url":"http://%s"}],"load_balancer_policy":"round_robin","backend_type":"http"}`, addr))
	patch("routes.json", "]", `,{"id":"sink-route","name":"Sink","type":"http","rule":"PathPrefix(`+"`/sink`"+`)","middlewares":["strip-sink"],"service_id":"sink-service"}`)
	patch("middlewares.json", "]", `,{"id":"strip-sink","type":"stripprefix","config":{"prefixes":"/sink"}}`)
	// Backend connections idle out in seconds, not the default minute, so an
	// idle pool is not mistaken for a leak within a case's settle time.
	replaceInConfig(t, env, "global.json", `"transport": {}`, `"transport": {"idle_conn_timeout_seconds": 5}`)
}

// replaceInConfig rewrites one occurrence of old in a copied config file.
func replaceInConfig(t *testing.T, env *TestEnv, name, old, repl string) {
	t.Helper()
	p := filepath.Join(env.Dir, "config", name)
	b, err := os.ReadFile(p) // #nosec G304 -- the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		t.Fatalf("%s: no %q to replace", name, old)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), old, repl, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// holdUpgrades opens n WebSocket upgrades to path and then says nothing, for
// up to hold or until the gateway closes them. It reports how many the gateway
// let go on its own.
func holdUpgrades(t *testing.T, addr, path string, n int, hold time.Duration) {
	t.Helper()
	var closedByGateway, opened, switched atomic.Int64
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
				&tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- self-signed test cert
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			opened.Add(1)
			req := "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
				"X-Forwarded-For: 77.1." + strconv.Itoa(i/250) + "." + strconv.Itoa(1+i%250) + "\r\n\r\n"
			_ = c.SetDeadline(time.Now().Add(hold))
			if _, err := c.Write([]byte(req)); err != nil {
				return
			}
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				// Closed before answering: the gateway let go.
				closedByGateway.Add(1)
				return
			}
			if resp.StatusCode == http.StatusSwitchingProtocols {
				switched.Add(1)
			} else {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			// Say nothing, and wait for the gateway to hang up.
			_, err = br.ReadByte()
			if err != nil && !isTimeout(err) {
				closedByGateway.Add(1)
			}
		})
	}
	wg.Wait()
	t.Logf("%d opened, %d switched protocols, %d closed by the gateway within %s",
		opened.Load(), switched.Load(), closedByGateway.Load(), hold)
}

// holdSilent opens n connections, optionally with a TLS handshake, sends
// nothing and waits for the gateway to hang up.
func holdSilent(t *testing.T, addr string, tlsCfg *tls.Config, n int, hold time.Duration) {
	t.Helper()
	var opened, closedByGateway atomic.Int64
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			var c net.Conn
			var err error
			if tlsCfg != nil {
				c, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, tlsCfg)
			} else {
				c, err = net.DialTimeout("tcp", addr, 5*time.Second)
			}
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			opened.Add(1)
			_ = c.SetReadDeadline(time.Now().Add(hold))
			var b [1]byte
			if _, err := c.Read(b[:]); err != nil && !isTimeout(err) {
				closedByGateway.Add(1)
			}
		})
	}
	wg.Wait()
	t.Logf("%d opened, %d closed by the gateway within %s", opened.Load(), closedByGateway.Load(), hold)
}

// rapidReset opens conns HTTP/2 connections and on each sends streams
// HEADERS frames each followed at once by RST_STREAM (CVE-2023-44487).
func rapidReset(t *testing.T, addr string, conns, streams int) {
	t.Helper()
	var sent, refused atomic.Int64
	var wg sync.WaitGroup
	for range conns {
		wg.Go(func() {
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
				&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) // #nosec G402 -- self-signed test cert
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			if c.ConnectionState().NegotiatedProtocol != "h2" {
				t.Log("server did not negotiate h2")
				return
			}
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
				return
			}
			fr := http2.NewFramer(c, c)
			if err := fr.WriteSettings(); err != nil {
				return
			}
			var hb bytes.Buffer
			enc := hpack.NewEncoder(&hb)
			go func() {
				for {
					if _, err := fr.ReadFrame(); err != nil {
						return
					}
				}
			}()
			for i := range streams {
				hb.Reset()
				for _, h := range [][2]string{{":method", "GET"}, {":path", "/test/health"}, {":scheme", "https"},
					{":authority", "localhost"}, {"x-forwarded-for", "78.1.1." + strconv.Itoa(1+i%250)}} {
					_ = enc.WriteField(hpack.HeaderField{Name: h[0], Value: h[1]})
				}
				id := uint32(1 + 2*i)
				if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true}); err != nil {
					refused.Add(1)
					return
				}
				if err := fr.WriteRSTStream(id, http2.ErrCodeCancel); err != nil {
					refused.Add(1)
					return
				}
				sent.Add(1)
			}
		})
	}
	wg.Wait()
	t.Logf("%d header+reset pairs sent over %d connections; %d connections ended by the gateway early", sent.Load(), conns, refused.Load())
}

// dripChunked opens n POSTs with a chunked body and sends one small chunk
// every 200ms, never the last one, for up to hold.
func dripChunked(t *testing.T, addr, path string, n int, hold time.Duration) {
	t.Helper()
	var opened, closedByGateway atomic.Int64
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
				&tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- self-signed test cert
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			opened.Add(1)
			_ = c.SetDeadline(time.Now().Add(hold))
			req := "POST " + path + " HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n" +
				"Transfer-Encoding: chunked\r\nX-Forwarded-For: 79.1.1." + strconv.Itoa(1+i%250) + "\r\n\r\n"
			if _, err := c.Write([]byte(req)); err != nil {
				return
			}
			deadline := time.Now().Add(hold)
			for time.Now().Before(deadline) {
				if _, err := c.Write([]byte("5\r\n{\"a\":\r\n")); err != nil {
					closedByGateway.Add(1)
					return
				}
				time.Sleep(200 * time.Millisecond)
			}
		})
	}
	wg.Wait()
	t.Logf("%d opened, %d cut off by the gateway within %s", opened.Load(), closedByGateway.Load(), hold)
}

// addressFlood sends n requests, each from a new forwarded address, across the
// routes that keep per-address state: the rate limiter, the honeypot, the
// IP filter and the WAF.
func addressFlood(t *testing.T, client *http.Client, base string, n int) {
	t.Helper()
	paths := []string{"/ratelimit/x", "/secret-admin", "/blocked/x", "/test/x?q=1", "/synology/x"}
	var wg sync.WaitGroup
	var done atomic.Int64
	for w := range 32 {
		wg.Go(func() {
			for i := w; i < n; i += 32 {
				req, _ := http.NewRequest(http.MethodGet, base+paths[i%len(paths)], nil)
				req.Header.Set("X-Forwarded-For", fmt.Sprintf("%d.%d.%d.%d", 11+i%200, (i/200)%256, (i/51200)%256, 1+i%250))
				req.Header.Set("User-Agent", "flood/"+strconv.Itoa(i))
				fpDo(client, req)
				done.Add(1)
			}
		})
	}
	wg.Wait()
	t.Logf("%d requests from distinct addresses", done.Load())
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// goroutineProfile returns the goroutine count and the aggregated stacks from
// pprof's debug=1 listing, keyed by stack with their counts.
func goroutineProfile(t *testing.T, pprofPort int) (int, map[string]int) {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/debug/pprof/goroutine?debug=1", pprofPort))
	if err != nil {
		t.Fatalf("pprof goroutine fetch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	stacks := map[string]int{}
	total := 0
	for i, block := range strings.Split(string(b), "\n\n") {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		lines := strings.SplitN(block, "\n", 2)
		if i == 0 {
			f := strings.Fields(lines[0])
			total, _ = strconv.Atoi(f[len(f)-1])
			if len(lines) < 2 {
				continue
			}
			block = lines[1]
			lines = strings.SplitN(block, "\n", 2)
		}
		n, _ := strconv.Atoi(strings.Fields(lines[0])[0])
		key := ""
		if len(lines) > 1 {
			key = lines[1]
		}
		stacks[key] += n
	}
	return total, stacks
}

// settledGoroutines polls the goroutine count for up to wait and returns it
// once it has stopped falling.
func settledGoroutines(t *testing.T, pprofPort int, wait time.Duration) (int, map[string]int) {
	t.Helper()
	deadline := time.Now().Add(wait)
	last, stacks := goroutineProfile(t, pprofPort)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		n, s := goroutineProfile(t, pprofPort)
		if n >= last {
			// Not falling any more; give it one more interval and take that.
			time.Sleep(2 * time.Second)
			return goroutineProfile(t, pprofPort)
		}
		last, stacks = n, s
	}
	return last, stacks
}

// grownStacks lists the stacks that have more goroutines now than at the
// baseline, largest growth first.
func grownStacks(before, after map[string]int, top int) []string {
	type d struct {
		k string
		n int
	}
	var ds []d
	for k, n := range after {
		if g := n - before[k]; g > 0 {
			ds = append(ds, d{k, g})
		}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].n > ds[j].n })
	var out []string
	for i, x := range ds {
		if i >= top {
			break
		}
		out = append(out, fmt.Sprintf("+%d goroutines at:\n%s", x.n, x.k))
	}
	return out
}

// healthCheckLoops counts the goroutines running a proxy handler's health
// checks, from a goroutine profile.
func healthCheckLoops(stacks map[string]int) int {
	n := 0
	for stack, count := range stacks {
		if strings.Contains(stack, "runHealthCheck") {
			n += count
		}
	}
	return n
}

// heapInUseMiB is the live heap after a collection, from pprof's heap listing.
func heapInUseMiB(t *testing.T, pprofPort int) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://127.0.0.1:%d/debug/pprof/heap?debug=1&gc=1", pprofPort), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pprof heap fetch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "# HeapInuse = ") {
			n, _ := strconv.Atoi(strings.TrimPrefix(line, "# HeapInuse = "))
			return n >> 20
		}
	}
	return -1
}
