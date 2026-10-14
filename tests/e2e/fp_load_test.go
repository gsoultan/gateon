// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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
)

// The false-positive gates (make test-fp) replay the benign corpus one request
// at a time, in-process, against a fresh WAF. That is the right way to measure
// what the WAF thinks of a request's content, and it cannot see anything that
// depends on how much traffic there is: a pooled buffer reused while another
// request still holds it, a per-client counter that a busy client crosses, a
// cache that answers one client with another's verdict. Under load those turn a
// request that passes on its own into a refusal, and nothing in-process notices,
// because in-process there is no load.
//
// So this drives the same corpus through the real binary, pinned to the 2 core
// budget the deployment targets, from many clients at once behind a trusted
// proxy, and asks one question: does any request get a different answer under
// load than it gets on its own? The cold answer is recorded first, so recorded
// false positives (the corpus's known_fp entries) and the e2e config's own
// strictness are part of the baseline rather than noise in the result.
//
// Opt-in, because it saturates the machine:
//
//	GATEON_FP_LOAD_TEST=1 go test ./tests/e2e/ -run TestFalsePositivesUnderLoad -v -timeout 20m

const (
	fpLoadClients     = 256
	fpLoadConcurrency = 64
	fpLoadAttackers   = 24
	fpLoadDuration    = 60 * time.Second // override with GATEON_FP_LOAD_SECONDS
)

type fpSample struct {
	Name     string            `json:"name"`
	Method   string            `json:"method,omitempty"`
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
	Profiles []string          `json:"profiles,omitempty"`
}

// loadBenignCorpus reads the corpus make test-fp gates on. Samples that need an
// app profile are left out: the e2e config enables none, so their cold answer
// is a refusal and says nothing about load.
func loadBenignCorpus(t *testing.T, projectRoot string) []fpSample {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(projectRoot, "internal/middleware/security/waf/testdata/benign/*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("benign corpus not found: %v", err)
	}
	var out []fpSample
	for _, f := range files {
		fh, err := os.Open(f) // #nosec G304 -- path from a fixed glob in the checkout
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			var s fpSample
			if err := json.Unmarshal([]byte(line), &s); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if len(s.Profiles) == 0 {
				out = append(out, s)
			}
		}
		_ = fh.Close()
	}
	return out
}

// fpClient is one simulated end user: an address the trusted proxy in front
// reports, and a browser.
type fpClient struct {
	ip string
	ua string
}

var fpUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
}

// fpClients spreads clients over public, non-reserved space: the mitigation
// responder exempts private and loopback sources, so a load test from those
// would be measuring an allowlist. 198.51.100.0/24 is avoided because the mock
// backend's reputation feed lists it.
func fpClients(n int) []fpClient {
	out := make([]fpClient, n)
	for i := range out {
		out[i] = fpClient{
			ip: fmt.Sprintf("81.%d.%d.%d", 2+i/(250*250), (i/250)%250+1, i%250+1),
			ua: fpUserAgents[i%len(fpUserAgents)],
		}
	}
	return out
}

func fpRequest(base string, s fpSample, c fpClient) (*http.Request, error) {
	method := s.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if s.Body != "" {
		body = strings.NewReader(s.Body)
	}
	req, err := http.NewRequest(method, base+"/test"+s.Path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-Forwarded-For", c.ip)
	return req, nil
}

// fpDo sends one request and returns its status, 0 for a transport error.
func fpDo(client *http.Client, req *http.Request) int {
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// passed is what "the request got through" means here. Anything the mock
// backend answers is a pass; the gateway's refusals are 403, 406, 429 and its
// own 5xx.
func passed(status int) bool { return status >= 200 && status < 400 }

// useDefaultAnomalyDetection puts the shipped anomaly-detection settings back.
// The e2e config sets the threat threshold to 999999 and the check interval to
// an hour, which keeps the other specs deterministic and switches off exactly
// the volume-driven analysis a load test is for.
func useDefaultAnomalyDetection(t *testing.T, env *TestEnv) {
	t.Helper()
	path := filepath.Join(env.Dir, "config/global.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	var global map[string]any
	if err := json.Unmarshal(raw, &global); err != nil {
		t.Fatal(err)
	}
	global["anomaly_detection"] = map[string]any{"sensitivity": 0.5, "check_interval_seconds": 10}
	out, err := json.MarshalIndent(global, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// fpAttacks is what the attackers mixed into the run send. Each attacker is its
// own address, as the "same browser, different networks" chain scenario has
// it: the clients share the TLS fingerprint of Go's client, so an attacker
// that could move a shared score would refuse bystanders here.
var fpAttacks = []string{
	"/test/search?q=1%27%20OR%20%271%27%3D%271",
	"/test/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
	"/test/download?file=..%2F..%2F..%2Fetc%2Fpasswd",
	"/test/run?cmd=%3Bcat%20%2Fetc%2Fshadow",
	"/secret-admin",
	"/test/.env",
	"/test/wp-login.php",
}

var fpAttackerAgents = []string{"sqlmap/1.8.4#stable", "Nikto/2.5.0", "Mozilla/5.0 zgrab/0.x", "python-requests/2.32.3", "curl/8.6.0"}

// attack drives attack traffic from n attacker addresses until deadline, at a
// fixed pace so the benign workers keep the machine.
func attack(client *http.Client, base string, n int, deadline time.Time) (sent int64) {
	var wg sync.WaitGroup
	var count atomic.Int64
	for a := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := fmt.Sprintf("45.%d.%d.%d", 10+a/250, a%250+1, 7)
			for k := 0; time.Now().Before(deadline); k++ {
				req, err := http.NewRequest(http.MethodGet, base+fpAttacks[(a+k)%len(fpAttacks)], nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", fpAttackerAgents[(a+k)%len(fpAttackerAgents)])
				req.Header.Set("X-Forwarded-For", ip)
				fpDo(client, req)
				count.Add(1)
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	return count.Load()
}

func TestFalsePositivesUnderLoad(t *testing.T) {
	if os.Getenv("GATEON_FP_LOAD_TEST") != "1" {
		t.Skip("false positives under load: set GATEON_FP_LOAD_TEST=1 to run (builds and saturates the real binary)")
	}
	projectRoot, _ := filepath.Abs("../..")
	corpus := loadBenignCorpus(t, projectRoot)
	env := SetupTestEnv(t)
	mock := startMockBackend(t, projectRoot, env)
	defer func() { _ = mock.Process.Kill() }()
	useDefaultAnomalyDetection(t, env)

	// The deployment target: 2 cores, 2 GB. The loopback peer is the trusted
	// proxy, as a load balancer or CDN would be, so every simulated client is
	// its own address to every per-client control.
	cmd, httpsPort, _ := startGateon(t, projectRoot, env,
		"GOMAXPROCS=2",
		"GATEON_MEMORY_LIMIT=1536MiB",
		"GATEON_TRUSTED_PROXIES=127.0.0.1/32",
		// GATEON_TEST disables the reputation blocker unless this is set,
		// and a load test that leaves it out is not testing the chain.
		"GATEON_ENABLE_TEST_REPUTATION=1",
	)
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	base := fmt.Sprintf("https://127.0.0.1:%d", httpsPort)
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- self-signed test cert
			MaxIdleConns:        fpLoadConcurrency * 2,
			MaxIdleConnsPerHost: fpLoadConcurrency * 2,
		},
	}

	// Cold: every sample once, each from its own fresh /24, so no client has
	// any history when its answer is taken -- reputation is shared by a
	// browser on a /24 (ADR 0011), so neighbouring addresses would not do.
	cold := make([]int, len(corpus))
	for i, s := range corpus {
		req, err := fpRequest(base, s, fpClient{ip: fmt.Sprintf("82.%d.%d.1", 1+i/250, 1+i%250), ua: fpUserAgents[0]})
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		cold[i] = fpDo(client, req)
		if !passed(cold[i]) {
			t.Logf("cold refusal #%d %q from %s: %d", i, s.Name, req.Header.Get("X-Forwarded-For"), cold[i])
		}
	}
	coldPass := 0
	for _, st := range cold {
		if passed(st) {
			coldPass++
		}
	}
	t.Logf("cold: %d samples, %d pass on their own", len(corpus), coldPass)

	dur := fpLoadDuration
	if s := os.Getenv("GATEON_FP_LOAD_SECONDS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			dur = time.Duration(n) * time.Second
		}
	}

	type flip struct {
		sample, client string
		cold, hot      int
	}
	var (
		total, refused atomic.Int64
		mu             sync.Mutex
		flips          = map[string]int{} // "sample|cold->hot" -> count
		examples       = map[string]flip{}
		byStatus       = map[int]int{}
	)
	clients := fpClients(fpLoadClients)
	deadline := time.Now().Add(dur)
	var attacks atomic.Int64
	var wg sync.WaitGroup
	wg.Go(func() { attacks.Store(attack(client, base, fpLoadAttackers, deadline)) })
	for w := range fpLoadConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; time.Now().Before(deadline); n++ {
				// Each worker walks the corpus and the clients at different
				// strides, so every client sends a mix of samples over the run.
				i := (w*7 + n*13) % len(corpus)
				c := clients[(w*31+n)%len(clients)]
				if n%4 == 0 {
					// A quarter of the traffic is four busy addresses: an
					// office or a carrier NAT, one address for many users.
					c = clients[w%4]
				}
				if !passed(cold[i]) {
					continue // already refused on its own: not a load effect
				}
				req, err := fpRequest(base, corpus[i], c)
				if err != nil {
					continue
				}
				st := fpDo(client, req)
				total.Add(1)
				if passed(st) {
					continue
				}
				refused.Add(1)
				key := fmt.Sprintf("%s|%d->%d", corpus[i].Name, cold[i], st)
				mu.Lock()
				flips[key]++
				byStatus[st]++
				if _, ok := examples[key]; !ok {
					examples[key] = flip{sample: corpus[i].Name, client: c.ip, cold: cold[i], hot: st}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	t.Logf("attackers: %d addresses sent %d attack requests alongside", fpLoadAttackers, attacks.Load())
	t.Logf("under load for %s: %d requests that pass on their own, %d refused (%.4f%%), by status %v",
		dur, total.Load(), refused.Load(), 100*float64(refused.Load())/float64(max(total.Load(), 1)), byStatus)
	keys := make([]string, 0, len(flips))
	for k := range flips {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool { return flips[keys[a]] > flips[keys[b]] })
	for _, k := range keys {
		e := examples[k]
		t.Errorf("FALSE POSITIVE UNDER LOAD: %q passed alone (%d) and was refused %d times under load (%d), first from %s",
			e.sample, e.cold, flips[k], e.hot, e.client)
	}
	if total.Load() == 0 {
		t.Fatal("no requests were sent under load; the run is meaningless")
	}
}

// TestABusyClientIsNotRefusedEverywhere is the shape a busy office produces:
// one address goes over one route's rate limit. The limiter answering 429 on
// that route is the control working. What must not follow is a refusal on
// every other route, for that client or for the people next to it.
func TestABusyClientIsNotRefusedEverywhere(t *testing.T) {
	if os.Getenv("GATEON_FP_LOAD_TEST") != "1" {
		t.Skip("set GATEON_FP_LOAD_TEST=1 to run (builds and runs the real binary)")
	}
	projectRoot, _ := filepath.Abs("../..")
	env := SetupTestEnv(t)
	mock := startMockBackend(t, projectRoot, env)
	defer func() { _ = mock.Process.Kill() }()
	cmd, httpsPort, _ := startGateon(t, projectRoot, env,
		"GATEON_TRUSTED_PROXIES=127.0.0.1/32",
		"GATEON_ENABLE_TEST_REPUTATION=1",
	)
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	base := fmt.Sprintf("https://127.0.0.1:%d", httpsPort)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // #nosec G402 -- self-signed test cert
	}
	get := func(path, ip string) int {
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("User-Agent", fpUserAgents[0])
		req.Header.Set("X-Forwarded-For", ip)
		return fpDo(client, req)
	}

	const office, neighbour = "81.77.1.10", "81.77.1.11"
	limited := 0
	for range 60 {
		if get("/ratelimit", office) == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("the rate limit never answered 429; the test is not exercising it")
	}
	// Threats are recorded off the request path, and what would refuse the
	// next request is the score they leave. There is nothing to poll for when
	// the right answer is that nothing changes, so give the loop its time.
	time.Sleep(2 * time.Second)
	for _, ip := range []string{office, neighbour} {
		if st := get("/test/dashboard", ip); !passed(st) {
			t.Errorf("%s was refused with %d on an unrelated route after %d rate-limit answers from %s",
				ip, st, limited, office)
		}
	}
}
