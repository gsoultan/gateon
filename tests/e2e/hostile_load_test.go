// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"

	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// What a hostile client sends that no benign corpus does: malformed encodings,
// oversized and deeply nested bodies, broken multipart, header floods, and
// requests cut off half way. A gateway on the 2 core / 2 GB target has to
// answer every one of them with a 4xx or close the connection; a 5xx, a panic
// in the log, or goroutines and memory that do not come back down are each a
// way one client takes the gateway down for everyone else.
//
// Opt-in, because it saturates the machine:
//
//	GATEON_FP_LOAD_TEST=1 go test ./tests/e2e/ -run TestHostileInputUnderLoad -v -timeout 20m

type hostileCase struct {
	name string
	req  func(base string) (*http.Request, error)
}

func hostileCases() []hostileCase {
	deepJSON := strings.Repeat(`{"a":`, 20000) + "1" + strings.Repeat("}", 20000)
	wideJSON := "[" + strings.Repeat(`"x",`, 200000) + `"x"]`
	bigForm := strings.Repeat("a=b&", 250000)
	brokenMultipart := "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.php\"\r\n" +
		"Content-Type: application/x-php\r\n\r\n<?php system($_GET['c']); ?>\r\n--b" // no closing boundary
	nestedMultipart := "--b\r\nContent-Type: multipart/mixed; boundary=c\r\n\r\n" +
		strings.Repeat("--c\r\nContent-Type: multipart/mixed; boundary=c\r\n\r\n", 2000) + "--b--\r\n"
	post := func(path, ctype, body string) func(string) (*http.Request, error) {
		return func(base string) (*http.Request, error) {
			r, err := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
			if err == nil {
				r.Header.Set("Content-Type", ctype)
			}
			return r, err
		}
	}
	get := func(path string, hdr map[string]string) func(string) (*http.Request, error) {
		return func(base string) (*http.Request, error) {
			r, err := http.NewRequest(http.MethodGet, base+path, nil)
			if err == nil {
				for k, v := range hdr {
					r.Header.Set(k, v)
				}
			}
			return r, err
		}
	}
	return []hostileCase{
		{"deep json", post("/test/api", "application/json", deepJSON)},
		{"wide json", post("/test/api", "application/json", wideJSON)},
		{"huge form", post("/test/form", "application/x-www-form-urlencoded", bigForm)},
		{"broken multipart", post("/test/upload", "multipart/form-data; boundary=b", brokenMultipart)},
		{"nested multipart", post("/test/upload", "multipart/form-data; boundary=b", nestedMultipart)},
		{"multipart no boundary", post("/test/upload", "multipart/form-data", "--x\r\n\r\n")},
		{"invalid utf8 json", post("/test/api", "application/json", "{\"a\":\"\xff\xfe\xc3\x28\"}")},
		{"xml entity bomb", post("/test/api", "application/xml",
			`<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">`+
				`<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]><l>&d;&d;&d;</l>`)},
		{"graphql depth", post("/test/graphql", "application/json",
			`{"query":"`+strings.Repeat("{a", 5000)+strings.Repeat("}", 5000)+`"}`)},
		{"bad percent", get("/test/%zz%%%u0000%c0%af?q=%E0%80%AF&x=%", nil)},
		{"long path", get("/test/"+strings.Repeat("a/", 8000), nil)},
		{"long query", get("/test/?"+strings.Repeat("k=v&", 6000), nil)},
		{"many params same name", get("/test/?"+strings.Repeat("id=1&", 4000), nil)},
		{"null bytes", get("/test/a%00b?x=%00", map[string]string{"X-Note": "a\x01b"})},
		{"huge cookie", get("/test/", map[string]string{"Cookie": strings.Repeat("c=1; ", 3000)})},
		{"jwt garbage", get("/test/", map[string]string{"Authorization": "Bearer " + strings.Repeat("eyJ.", 2000)})},
		{"bad content-length body", post("/test/api", "application/json", "")},
		{"range flood", get("/test/", map[string]string{"Range": "bytes=" + strings.Repeat("0-1,", 2000) + "0-1"})},
		{"bad host", func(base string) (*http.Request, error) {
			r, err := http.NewRequest(http.MethodGet, base+"/test/", nil)
			if err == nil {
				r.Host = strings.Repeat("a.", 120) + "evil"
			}
			return r, err
		}},
		{"websocket upgrade garbage", get("/test/ws", map[string]string{
			"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Key": "%%%", "Sec-WebSocket-Version": "99",
		})},
	}
}

// startGateonLogged is startGateon with the process's output kept, so a
// recovered panic -- which still answers, or still closes, and so looks like
// any other refusal from outside -- is visible.
func startGateonLogged(t *testing.T, projectRoot string, env *TestEnv, logPath string, extraEnv ...string) (*exec.Cmd, int, int) {
	t.Helper()
	binary := filepath.Join(env.Dir, "gateon"+exeSuffix())
	build := exec.Command("go", "build", "-o", binary, "./cmd/gateon")
	build.Dir = projectRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	logFile, err := os.Create(logPath) // #nosec G304 -- the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	cmd := exec.Command(binary)
	cmd.Dir = projectRoot
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.Env = append(env.GatewayEnv(
		"GLOBAL_CONFIG_FILE="+filepath.Join(env.Dir, "config/global.json"),
		"ROUTES_FILE="+filepath.Join(env.Dir, "config/routes.json"),
		"SERVICES_FILE="+filepath.Join(env.Dir, "config/services.json"),
		"ENTRYPOINTS_FILE="+filepath.Join(env.Dir, "config/entrypoints.json"),
		"MIDDLEWARES_FILE="+filepath.Join(env.Dir, "config/middlewares.json"),
		"TLS_OPTIONS_FILE="+filepath.Join(env.Dir, "config/tls_options.json"),
		fmt.Sprintf("GATEON_PPROF_ADDR=127.0.0.1:%d", env.Ports["pprof"]),
	), extraEnv...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitForPort(t, env.Ports["http_tls"])
	return cmd, env.Ports["http_tls"], env.Ports["pprof"]
}

// slowloris opens a TLS connection, sends half a request and holds it.
func slowloris(addr string, hold time.Duration) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- self-signed test cert
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("POST /test/ HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\nab"))
	time.Sleep(hold)
}

func TestHostileInputUnderLoad(t *testing.T) {
	if os.Getenv("GATEON_FP_LOAD_TEST") != "1" {
		t.Skip("hostile input under load: set GATEON_FP_LOAD_TEST=1 to run")
	}
	projectRoot, _ := filepath.Abs("../..")
	env := SetupTestEnv(t)
	mock := startMockBackend(t, projectRoot, env)
	defer func() { _ = mock.Process.Kill() }()
	logPath := filepath.Join(env.Dir, "gateon.log")
	cmd, port, pprofPort := startGateonLogged(t, projectRoot, env, logPath,
		"GOMAXPROCS=2", "GATEON_MEMORY_LIMIT=1536MiB", "GATEON_TRUSTED_PROXIES=127.0.0.1/32",
		"GATEON_ENABLE_TEST_REPUTATION=1")
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	base := fmt.Sprintf("https://127.0.0.1:%d", port)
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- self-signed test cert
			MaxIdleConnsPerHost: 64,
		},
	}

	// A benign probe that must keep answering 200 throughout.
	probe := func() int {
		req, _ := http.NewRequest(http.MethodGet, base+"/test/health", nil)
		req.Header.Set("X-Forwarded-For", "81.200.1.1")
		return fpDo(client, req)
	}
	if st := probe(); st != http.StatusOK {
		t.Fatalf("probe before the run: %d", st)
	}
	baseG := goroutineCount(t, pprofPort)
	baseRSS := rssKB(cmd.Process.Pid)

	cases := hostileCases()
	var mu sync.Mutex
	results := make(map[string]map[int]int, len(cases))
	var probeFails, probes atomic.Int64
	var peakRSS atomic.Int64
	deadline := time.Now().Add(fpLoadDurationOr(60 * time.Second))
	var wg sync.WaitGroup
	for w := range 32 {
		wg.Go(func() {
			for n := 0; time.Now().Before(deadline); n++ {
				c := cases[(w+n)%len(cases)]
				req, err := c.req(base)
				if err != nil {
					continue
				}
				req.Header.Set("X-Forwarded-For", fmt.Sprintf("46.%d.%d.%d", 1+w, 1+n%250, 1+(n/250)%250))
				st := fpDo(client, req)
				mu.Lock()
				if results[c.name] == nil {
					results[c.name] = map[int]int{}
				}
				results[c.name][st]++
				mu.Unlock()
			}
		})
	}
	for range 64 {
		wg.Go(func() {
			for time.Now().Before(deadline) {
				slowloris(fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
			}
		})
	}
	wg.Go(func() {
		for time.Now().Before(deadline) {
			probes.Add(1)
			if probe() != http.StatusOK {
				probeFails.Add(1)
			}
			if r := int64(rssKB(cmd.Process.Pid)); r > peakRSS.Load() {
				peakRSS.Store(r)
				if dir := os.Getenv("GATEON_HOSTILE_HEAP_DIR"); dir != "" {
					saveHeap(pprofPort, filepath.Join(dir, "heap.pb.gz"))
				}
			}
			time.Sleep(250 * time.Millisecond)
		}
	})
	wg.Wait()

	for _, c := range cases {
		t.Logf("%-26s %v", c.name, results[c.name])
		for st, n := range results[c.name] {
			if st >= 500 {
				t.Errorf("%s: %d answers with %d; hostile input must be refused, not fail the gateway", c.name, n, st)
			}
		}
	}
	t.Logf("benign probe during the run: %d of %d failed", probeFails.Load(), probes.Load())
	if probeFails.Load() > 0 {
		t.Errorf("a benign client was refused or timed out %d times while the hostile load ran", probeFails.Load())
	}

	client.CloseIdleConnections() // our own keep-alive connections are not a leak
	time.Sleep(10 * time.Second)  // let slowloris connections time out and pools settle
	finalG := goroutineCount(t, pprofPort)
	t.Logf("goroutines %d -> %d, rss %d MB -> peak %d MB -> %d MB",
		baseG, finalG, baseRSS/1024, peakRSS.Load()/1024, rssKB(cmd.Process.Pid)/1024)
	if finalG > baseG+60 {
		t.Errorf("goroutines did not come back down after the run: %d -> %d", baseG, finalG)
	}
	if peakRSS.Load() > 2*1024*1024 {
		t.Errorf("peak RSS %d MB is over the 2 GB target", peakRSS.Load()/1024)
	}

	logs, _ := os.ReadFile(logPath) // #nosec G304 -- the test's own temp dir
	for _, line := range bytes.Split(logs, []byte("\n")) {
		l := strings.ToLower(string(line))
		if strings.Contains(l, "panic") || strings.Contains(l, "fatal error") || strings.Contains(l, "data race") {
			t.Errorf("gateway log: %s", line)
		}
	}
}

func fpLoadDurationOr(def time.Duration) time.Duration {
	if s := os.Getenv("GATEON_FP_LOAD_SECONDS"); s != "" {
		if d, err := time.ParseDuration(s + "s"); err == nil && d > 0 {
			return d
		}
	}
	return def
}

func saveHeap(pprofPort int, path string) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/debug/pprof/heap", pprofPort))
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err == nil {
		_ = os.WriteFile(path, b, 0o600)
	}
}

// TestALargeBodyFloodLeavesRoomForEveryoneElse: 600 clients from 600 addresses
// each posting a 1 MiB form stay inside every per-address and per-connection
// cap, and inspecting each body holds several times its length. Unbounded, that
// took the gateway to 1.73 GB on a 2 GB budget and timed out small requests
// from unrelated users. The large-body slots must shed the flood instead.
func TestALargeBodyFloodLeavesRoomForEveryoneElse(t *testing.T) {
	if os.Getenv("GATEON_FP_LOAD_TEST") != "1" {
		t.Skip("large-body flood: set GATEON_FP_LOAD_TEST=1 to run")
	}
	projectRoot, _ := filepath.Abs("../..")
	env := SetupTestEnv(t)
	mock := startMockBackend(t, projectRoot, env)
	defer func() { _ = mock.Process.Kill() }()
	cmd, port, _ := startGateonLogged(t, projectRoot, env, filepath.Join(env.Dir, "gateon.log"),
		"GOMAXPROCS=2", "GATEON_MEMORY_LIMIT=1024MiB", "GATEON_TRUSTED_PROXIES=127.0.0.1/32")
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	base := fmt.Sprintf("https://127.0.0.1:%d", port)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- self-signed test cert
			MaxIdleConnsPerHost: 700,
		},
	}
	form := bytes.Repeat([]byte("a=b&"), (1<<20)/4)

	var mu sync.Mutex
	statuses := map[int]int{}
	var peakRSS atomic.Int64
	var probeFails, probes atomic.Int64
	deadline := time.Now().Add(fpLoadDurationOr(30 * time.Second))
	var wg sync.WaitGroup
	for c := range 600 {
		wg.Go(func() {
			for time.Now().Before(deadline) {
				req, _ := http.NewRequest(http.MethodPost, base+"/test/upload", bytes.NewReader(form))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("X-Forwarded-For", fmt.Sprintf("47.1.%d.%d", 1+c/250, 1+c%250))
				st := fpDo(client, req)
				mu.Lock()
				statuses[st]++
				mu.Unlock()
			}
		})
	}
	wg.Go(func() {
		for time.Now().Before(deadline) {
			req, _ := http.NewRequest(http.MethodGet, base+"/test/health", nil)
			req.Header.Set("X-Forwarded-For", "81.200.1.1")
			probes.Add(1)
			// Slow is failed: a small request that waits seconds behind a
			// flood it has nothing to do with is a user who has left.
			start := time.Now()
			if fpDo(client, req) != http.StatusOK || time.Since(start) > 2*time.Second {
				probeFails.Add(1)
			}
			if r := int64(rssKB(cmd.Process.Pid)); r > peakRSS.Load() {
				peakRSS.Store(r)
			}
			time.Sleep(500 * time.Millisecond)
		}
	})
	wg.Wait()

	t.Logf("large posts by status %v; benign probe %d of %d failed; peak RSS %d MB",
		statuses, probeFails.Load(), probes.Load(), peakRSS.Load()/1024)
	if probeFails.Load() > 0 {
		t.Errorf("a small request from an unrelated client failed or took over 2s %d times during the flood", probeFails.Load())
	}
	if peakRSS.Load() > 1100*1024 {
		t.Errorf("peak RSS %d MB is past the 1 GiB memory limit", peakRSS.Load()/1024)
	}
	if statuses[0] > 0 {
		t.Errorf("%d large posts timed out or were dropped; a shed body is answered 503, not left hanging", statuses[0])
	}
}
