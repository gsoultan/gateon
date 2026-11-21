// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The compatibility specs run two real binaries against one set of state:
// the last release, and the build of this checkout (ADR 0100). They are what
// holds a change to the rule that a gateway can be upgraded from the previous
// release and put back.
const (
	// envPreviousBinary names the last release's gateon binary.
	envPreviousBinary = "GATEON_COMPAT_PREVIOUS"
	// envCompatRequired turns a missing previous binary from a skip into a
	// failure. `make check-compat` sets it, so the gate cannot pass by not
	// running.
	envCompatRequired = "GATEON_COMPAT_REQUIRED"
	// envCompatPostgres is a PostgreSQL server the specs may create a
	// database on. It is the variable the rest of the suite uses.
	envCompatPostgres = "GATEON_TEST_POSTGRES_DSN"

	compatReadyTimeout = 90 * time.Second
	compatStopTimeout  = 60 * time.Second
	compatProxyPath    = "/test/compat"
	compatUserAgent    = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

// previousBinary is the last release's binary, or the test skips. Under
// `make check-compat` a missing one fails instead.
func previousBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv(envPreviousBinary)
	if path == "" {
		if os.Getenv(envCompatRequired) == "1" {
			t.Fatalf("%s is not set and %s=1: the compatibility gate has nothing to compare against", envPreviousBinary, envCompatRequired)
		}
		t.Skipf("set %s to the last release's gateon binary to run (make check-compat does)", envPreviousBinary)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s: %v", envPreviousBinary, err)
	}
	return path
}

// startCompatBackend serves what the e2e routes proxy to, in this process.
func startCompatBackend(t *testing.T, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listen for the backend: %v", err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"backend":"compat"}`)
		}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = srv.Close()
		<-done
	})
}

// compatGateway is one gateon process under test.
type compatGateway struct {
	t    *testing.T
	name string
	cmd  *exec.Cmd
	log  string
	done chan error
}

// compatStart describes how to start a gateway: which binary, on which state,
// and what a service manager would add.
type compatStart struct {
	name   string
	binary string
	env    *TestEnv
	// extraEnv is added to the environment as given.
	extraEnv []string
	// passed is sockets handed over the way systemd does: they become
	// descriptors 3 and up, announced by LISTEN_FDS and LISTEN_FDNAMES.
	passed []*os.File
	names  []string
}

// startCompatGateway starts the process and returns once it has started; it
// does not wait for it to be ready.
func startCompatGateway(t *testing.T, s compatStart) *compatGateway {
	t.Helper()
	logPath := filepath.Join(s.env.Dir, s.name+".log")
	logFile, err := os.Create(logPath) // #nosec G304 -- a path under the test's temp dir
	if err != nil {
		t.Fatalf("create %s: %v", logPath, err)
	}
	cfg := func(f string) string { return filepath.Join(s.env.Dir, "config", f) }
	env := s.env.GatewayEnv(
		"GLOBAL_CONFIG_FILE="+cfg("global.json"),
		"ROUTES_FILE="+cfg("routes.json"),
		"SERVICES_FILE="+cfg("services.json"),
		"ENTRYPOINTS_FILE="+cfg("entrypoints.json"),
		"MIDDLEWARES_FILE="+cfg("middlewares.json"),
		"TLS_OPTIONS_FILE="+cfg("tls_options.json"),
	)
	env = append(env, s.extraEnv...)

	cmd := exec.Command(s.binary) // #nosec G204 -- a binary the test built or was given
	if len(s.passed) > 0 {
		// LISTEN_PID must be the gateway's own pid, which is only known
		// once it exists: the shell sets it and then becomes the gateway.
		cmd = exec.Command("/bin/sh", "-c", `LISTEN_PID=$$ exec "$0"`, s.binary) // #nosec G204 -- as above
		cmd.ExtraFiles = s.passed
		env = append(env,
			"LISTEN_FDS="+strconv.Itoa(len(s.passed)),
			"LISTEN_FDNAMES="+strings.Join(s.names, ":"),
		)
	}
	cmd.Dir = s.env.Dir
	cmd.Env = env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("start %s: %v", s.name, err)
	}
	_ = logFile.Close()

	g := &compatGateway{t: t, name: s.name, cmd: cmd, log: logPath, done: make(chan error, 1)}
	go func() { g.done <- cmd.Wait() }()
	t.Cleanup(func() {
		if g.cmd.ProcessState == nil {
			_ = g.cmd.Process.Kill()
			<-g.done
		}
		if t.Failed() {
			g.dumpLog()
		}
	})
	return g
}

// dumpLog prints the end of the process's own log, for a failure.
func (g *compatGateway) dumpLog() {
	data, err := os.ReadFile(g.log)
	if err != nil {
		return
	}
	const tail = 6000
	if len(data) > tail {
		data = data[len(data)-tail:]
	}
	g.t.Logf("---- %s log (tail) ----\n%s", g.name, data)
}

// waitReady waits for /readyz on the management listener to answer 200, and
// fails if the process exits first.
func (g *compatGateway) waitReady(mgmtPort int) {
	g.t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/readyz", mgmtPort)
	deadline := time.Now().Add(compatReadyTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-g.done:
			g.done <- err
			g.t.Fatalf("%s exited before it was ready: %v", g.name, err)
		default:
		}
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	g.t.Fatalf("%s was not ready within %s", g.name, compatReadyTimeout)
}

// stop asks the process to shut down the way systemd does and waits for it.
func (g *compatGateway) stop() {
	g.t.Helper()
	if err := g.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		g.t.Fatalf("signal %s: %v", g.name, err)
	}
	select {
	case <-g.done:
		g.done <- nil
	case <-time.After(compatStopTimeout):
		g.t.Fatalf("%s did not exit within %s of SIGTERM", g.name, compatStopTimeout)
	}
}

// proxied makes one request through the plaintext entrypoint on a connection
// of its own and returns the status, or the error that stopped it.
func proxied(port int, timeout time.Duration) (int, error) {
	tr := &http.Transport{DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, compatProxyPath), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", compatUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// requireProxied fails unless a request through the gateway reaches the
// backend.
func requireProxied(t *testing.T, who string, port int) {
	t.Helper()
	status, err := proxied(port, 10*time.Second)
	if err != nil {
		t.Fatalf("%s: a request through the gateway failed: %v", who, err)
	}
	if status != http.StatusOK {
		t.Fatalf("%s: a request through the gateway answered %d, want 200", who, status)
	}
}

// fdManager is the part of systemd the socket handoff talks to: it receives
// the sockets a gateway hands over (sd_notify FDSTORE=1 with SCM_RIGHTS) and
// keeps them open, to pass to the next process.
type fdManager struct {
	t    *testing.T
	path string
	conn *net.UnixConn

	mu    sync.Mutex
	files map[string]*os.File
}

func startFDManager(t *testing.T) *fdManager {
	t.Helper()
	// A short path: a Unix socket address has about a hundred bytes.
	dir, err := os.MkdirTemp("", "gwn")
	if err != nil {
		t.Fatalf("temp dir for the notify socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "n")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen on the notify socket: %v", err)
	}
	m := &fdManager{t: t, path: path, conn: conn, files: make(map[string]*os.File)}
	go m.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, f := range m.files {
			_ = f.Close()
		}
	})
	return m
}

func (m *fdManager) serve() {
	buf := make([]byte, 4096)
	oob := make([]byte, 4096)
	for {
		n, oobn, _, _, err := m.conn.ReadMsgUnix(buf, oob)
		if err != nil {
			return
		}
		m.handle(string(buf[:n]), oob[:oobn])
	}
}

func (m *fdManager) handle(state string, oob []byte) {
	fields := map[string]string{}
	for line := range strings.SplitSeq(state, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			fields[k] = v
		}
	}
	name := fields["FDNAME"]
	m.mu.Lock()
	defer m.mu.Unlock()
	if fields["FDSTOREREMOVE"] == "1" {
		if f := m.files[name]; f != nil {
			_ = f.Close()
			delete(m.files, name)
		}
		return
	}
	if fields["FDSTORE"] != "1" {
		return
	}
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for _, msg := range msgs {
		fds, err := syscall.ParseUnixRights(&msg)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			syscall.CloseOnExec(fd)
			if old := m.files[name]; old != nil {
				_ = old.Close()
			}
			m.files[name] = os.NewFile(uintptr(fd), name) // #nosec G115 -- a descriptor number
		}
	}
}

// held is the sockets being kept, in a stable order, with their names.
func (m *fdManager) held() (files []*os.File, names []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name := range m.files {
		names = append(names, name)
	}
	// Sorted, so a failure reads the same from run to run.
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, name := range names {
		files = append(files, m.files[name])
	}
	return files, names
}

// waitHeld waits until the manager holds at least n sockets.
func (m *fdManager) waitHeld(n int) {
	m.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if files, _ := m.held(); len(files) >= n {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	files, names := m.held()
	m.t.Fatalf("the gateway handed over %d sockets (%v), want at least %d", len(files), names, n)
}
