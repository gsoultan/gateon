// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package e2e

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/db"
)

// compatDatabases are the stores a gateway keeps its state in. Both are
// supported, so the rule is held on both.
func compatDatabases(t *testing.T) map[string]func(t *testing.T, env *TestEnv) {
	return map[string]func(t *testing.T, env *TestEnv){
		"sqlite":   func(*testing.T, *TestEnv) {},
		"postgres": usePostgres,
	}
}

// usePostgres points the gateway's configuration at a new, empty PostgreSQL
// database, so that the previous release is the one that creates its schema.
func usePostgres(t *testing.T, env *TestEnv) {
	t.Helper()
	dsn := os.Getenv(envCompatPostgres)
	if dsn == "" {
		if os.Getenv(envCompatRequired) == "1" {
			t.Fatalf("%s is not set and %s=1: PostgreSQL would go unchecked", envCompatPostgres, envCompatRequired)
		}
		t.Skipf("%s not set", envCompatPostgres)
	}
	base, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("%s: %v", envCompatPostgres, err)
	}
	admin, _, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("open %s: %v", base.Redacted(), err)
	}
	name := fmt.Sprintf("gateon_compat_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		_ = admin.Close()
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"); err != nil {
			t.Logf("drop %s: %v", name, err)
		}
		_ = admin.Close()
	})
	target := *base
	target.Path = "/" + name
	rewriteDatabaseURL(t, env, target.String())
}

// rewriteDatabaseURL replaces the SQLite path SetupTestEnv wrote into
// global.json with to.
func rewriteDatabaseURL(t *testing.T, env *TestEnv, to string) {
	t.Helper()
	path := filepath.Join(env.Dir, "config", "global.json")
	data, err := os.ReadFile(path) // #nosec G304 -- a path under the test's temp dir
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	from := filepath.Join(env.Dir, "gateon_test.db")
	if !strings.Contains(string(data), from) {
		t.Fatalf("%s does not name %s; the e2e config changed and this needs to follow", path, from)
	}
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(data), from, to)), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// appliedMigrations is how many migrations the database at env records.
func appliedMigrations(t *testing.T, env *TestEnv) int {
	t.Helper()
	path := filepath.Join(env.Dir, "config", "global.json")
	data, err := os.ReadFile(path) // #nosec G304 -- a path under the test's temp dir
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	_, rest, ok := strings.Cut(string(data), `"database_url": "`)
	if !ok {
		t.Fatalf("%s has no database_url", path)
	}
	dsn, _, _ := strings.Cut(rest, `"`)
	conn, _, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("open the gateway's database: %v", err)
	}
	defer func() { _ = conn.Close() }()
	var n int
	if err := conn.QueryRow("SELECT COUNT(*) FROM migrations").Scan(&n); err != nil && err != sql.ErrNoRows {
		t.Fatalf("count applied migrations: %v", err)
	}
	return n
}

// TestTheLastReleaseUpgradesToThisBuildAndBack is the compatibility rule as a
// test. The last release creates the configuration and the database; this
// build must start on them and serve; and then the last release must start
// again on what this build left behind, because that is what a rollback is.
//
// The third step is the one a forward-only migration breaks: a column this
// build drops or renames is one the last release still reads.
func TestTheLastReleaseUpgradesToThisBuildAndBack(t *testing.T) {
	previous := previousBinary(t)
	for name, prepare := range compatDatabases(t) {
		t.Run(name, func(t *testing.T) {
			env := SetupTestEnv(t)
			prepare(t, env)
			startCompatBackend(t, env.Ports["mock_backend"])

			run := func(who, binary string) {
				g := startCompatGateway(t, compatStart{name: who, binary: binary, env: env})
				g.waitReady(env.Ports["mgmt"])
				requireProxied(t, who, env.Ports["http_plain"])
				g.stop()
			}

			run("1-previous", previous)
			before := appliedMigrations(t, env)
			if before == 0 {
				t.Fatal("the previous release recorded no migrations; it did not create the database this test is about")
			}

			run("2-this-build", env.BinaryPath)
			after := appliedMigrations(t, env)
			if after < before {
				t.Fatalf("this build left %d applied migrations where the previous release had %d", after, before)
			}
			t.Logf("migrations applied: %d by the previous release, %d after this build", before, after)

			run("3-previous-again", previous)
		})
	}
}

// restartFailure is one request that was not answered 200 across a restart.
type restartFailure struct {
	at   time.Duration // since the load began
	what string
}

// restartLoad is a client that opens a new connection for every request, the
// case a restart is hardest on: nothing is kept alive to retry over.
type restartLoad struct {
	port  int
	began time.Time
	sent  atomic.Int64
	stop  chan struct{}
	wg    sync.WaitGroup

	mu       sync.Mutex
	failures []restartFailure
}

func startRestartLoad(port int) *restartLoad {
	l := &restartLoad{port: port, began: time.Now(), stop: make(chan struct{})}
	for range 4 {
		l.wg.Go(l.run)
	}
	return l
}

func (l *restartLoad) run() {
	for {
		select {
		case <-l.stop:
			return
		default:
		}
		l.sent.Add(1)
		// Longer than the restart: a request that waits is the point, and
		// one that gives up would look like a refusal.
		status, err := proxied(l.port, compatReadyTimeout)
		if err != nil || status != 200 {
			l.mu.Lock()
			l.failures = append(l.failures, restartFailure{
				at:   time.Since(l.began),
				what: fmt.Sprintf("status %d, error %v", status, err),
			})
			l.mu.Unlock()
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (l *restartLoad) since() time.Duration { return time.Since(l.began) }

// finish stops the load and returns what failed.
func (l *restartLoad) finish() []restartFailure {
	close(l.stop)
	l.wg.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failures
}

// restartOutcome is what restartUnderLoad saw.
type restartOutcome struct {
	total int64
	// oldExited is when the old gateway's process ended. A failure before it
	// is the old binary's doing; one after it is the new binary's, or the
	// handed-over socket's.
	oldExited time.Duration
	failures  []restartFailure
}

// restartUnderLoad restarts oldBinary into this build the way an upgrade
// does, with the listening sockets kept open by a service manager, while a
// client opens a new connection for every request. An empty oldBinary is this
// build too.
func restartUnderLoad(t *testing.T, oldBinary string) restartOutcome {
	t.Helper()
	env := SetupTestEnv(t)
	if oldBinary == "" {
		oldBinary = env.BinaryPath
	}
	startCompatBackend(t, env.Ports["mock_backend"])
	manager := startFDManager(t)
	notify := "NOTIFY_SOCKET=" + manager.path

	old := startCompatGateway(t, compatStart{name: "1-old", binary: oldBinary, env: env, extraEnv: []string{notify}})
	old.waitReady(env.Ports["mgmt"])
	requireProxied(t, "the old gateway", env.Ports["http_plain"])
	// The management listener and the plaintext entrypoint at the least.
	manager.waitHeld(2)

	load := startRestartLoad(env.Ports["http_plain"])
	// Let the load run against the old gateway, then replace it.
	time.Sleep(500 * time.Millisecond)
	beforeRestart := load.sent.Load()
	old.stop()
	out := restartOutcome{oldExited: load.since()}
	files, names := manager.held()
	if len(files) < 2 {
		t.Fatalf("the service manager held %d sockets after the old gateway exited (%v), want at least 2", len(files), names)
	}
	// Nothing is accepting now. Requests made in this gap are the ones that
	// used to be refused.
	time.Sleep(500 * time.Millisecond)
	inGap := load.sent.Load() - beforeRestart

	fresh := startCompatGateway(t, compatStart{
		name: "2-new", binary: env.BinaryPath, env: env,
		extraEnv: []string{notify}, passed: files, names: names,
	})
	fresh.waitReady(env.Ports["mgmt"])
	time.Sleep(500 * time.Millisecond)
	out.failures = load.finish()
	out.total = load.sent.Load()
	fresh.stop()

	t.Logf("%d requests: %d before the restart, %d started while no gateway was running, %d failed; the old gateway exited at %s",
		out.total, beforeRestart, inGap, len(out.failures), out.oldExited.Round(time.Millisecond))
	if inGap == 0 {
		t.Fatal("no request was started while the gateway was down; the test did not exercise the gap")
	}
	return out
}

// TestARestartOfThisBuildLosesNoRequest is the whole claim, for the part this
// build answers for on both sides: its own shutdown and its own start. A
// connection the old process had accepted is answered before it exits, and
// one made while nothing is running waits in the socket for the new process.
// Not one request may fail.
func TestARestartOfThisBuildLosesNoRequest(t *testing.T) {
	out := restartUnderLoad(t, "")
	if n := len(out.failures); n != 0 {
		first := out.failures[0]
		t.Fatalf("%d of %d requests failed across the restart (first: %s, %s after the load began)",
			n, out.total, first.what, first.at.Round(time.Millisecond))
	}
}

// TestARestartIntoThisBuildRefusesNoConnection restarts the last release into
// this build, which is what an upgrade is. This build cannot change how the
// last release shuts down, so a request the old process dropped on its way
// out is reported and not held against this one. Everything after the old
// process has gone is this build's: a connection made then must wait and be
// answered.
func TestARestartIntoThisBuildRefusesNoConnection(t *testing.T) {
	out := restartUnderLoad(t, previousBinary(t))
	for _, f := range out.failures {
		if f.at <= out.oldExited {
			t.Logf("the previous release dropped a request while it shut down (%s, %s after the load began)",
				f.what, f.at.Round(time.Millisecond))
			continue
		}
		t.Errorf("a request failed after the previous release had exited (%s, %s after the load began): "+
			"a connection made during an upgrade must wait and be served", f.what, f.at.Round(time.Millisecond))
	}
}
