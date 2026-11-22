// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package e2e

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/selfupdate/helper"
	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
)

// rollbackVersion is what this build calls itself in the rollback spec. It
// only has to be a release other than the previous one.
const rollbackVersion = "99.0.0"

// claimHelperState takes the upgrade helper's directory for one test. Every
// gateway, the last release's included, reads it at one fixed path, so the
// spec cannot use a directory of its own. It refuses a directory that
// already holds a helper's record: that is a host with a real gateon on it.
func claimHelperState(t *testing.T) string {
	t.Helper()
	dir := upgrade.DefaultStateDir
	unusable := func(format string, args ...any) {
		t.Helper()
		if os.Getenv(envCompatRequired) == "1" {
			t.Fatalf(format, args...)
		}
		t.Skipf(format, args...)
	}
	created := false
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// #nosec G301 -- the helper's directory is world-readable by design.
		if err := os.Mkdir(dir, 0o755); err != nil {
			unusable("%s cannot be created (%v): create it and give it to this account, as `make check-compat` does", dir, err)
		}
		created = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		unusable("%s cannot be read: %v", dir, err)
	}
	if len(entries) != 0 {
		unusable("%s is not empty: it belongs to a gateon installed on this host, and this spec would overwrite its record", dir)
	}
	probe := filepath.Join(dir, ".writable")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		unusable("%s is not writable by this account: %v", dir, err)
	}
	_ = os.Remove(probe)
	t.Cleanup(func() {
		left, _ := os.ReadDir(dir)
		for _, e := range left {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
		if created {
			_ = os.Remove(dir)
		}
	})
	return dir
}

// buildAsRelease builds this checkout as the release after previous: named
// rollbackVersion and declared compatible with previous, which is what the
// release workflow does once the compatibility specs have passed (ADR 0102).
func buildAsRelease(t *testing.T, previous string) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "gateon")
	flags := "-X main.Version=" + rollbackVersion + " -X main.CompatibleWith=" + previous
	cmd := exec.Command("go", "build", "-ldflags", flags, "-o", out, "./cmd/gateon") // #nosec G204 -- fixed arguments and a version this test read
	cmd.Dir = root
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build this checkout as a release: %v\n%s", err, msg)
	}
	return out
}

func versionOf(t *testing.T, binary string) string {
	t.Helper()
	out, err := exec.Command(binary, "version").Output() // #nosec G204 -- a binary the test built or was given
	if err != nil {
		t.Fatalf("%s version: %v", binary, err)
	}
	return strings.TrimSpace(string(out))
}

func copyBinary(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src) // #nosec G304 -- a binary the test built or was given
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { // #nosec G301 -- under the test's temp dir
		t.Fatal(err)
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) // #nosec G302 G304 -- an executable under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	// Renamed into place, as the helper does: the running process keeps its file.
	if err := os.Rename(tmp, dst); err != nil {
		t.Fatal(err)
	}
}

// processService is the service manager of the spec: a restart stops the
// running gateway and starts whatever binary is installed now.
type processService struct {
	t       *testing.T
	env     *TestEnv
	binary  string
	running *compatGateway
	starts  int
}

func (s *processService) start() {
	s.t.Helper()
	s.starts++
	name := "gateway-" + string(rune('0'+s.starts))
	s.running = startCompatGateway(s.t, compatStart{name: name, binary: s.binary, env: s.env})
}

func (s *processService) Restart(context.Context) error {
	s.running.stop()
	s.start()
	return nil
}

func (s *processService) Restarts(context.Context) int { return 0 }

// TestAnUpgradeFromTheLastReleaseRollsBackOnRequest runs the rollback an
// operator asks for (ADR 0105) with nothing simulated but the service
// manager: this checkout's helper puts the last release's own binary back,
// and that binary, which was written before any of this existed, has to read
// the helper's status and answer it.
//
// It is the half of a rollback no test inside this repository's packages can
// hold: there, both sides are this checkout's code and agree by construction.
// The last release refuses a status file with a field it does not know, so a
// field added to that file since would end every rollback with the newer
// release put back after the timeout.
func TestAnUpgradeFromTheLastReleaseRollsBackOnRequest(t *testing.T) {
	previous := previousBinary(t)
	previousVersion := versionOf(t, previous)
	state := claimHelperState(t)
	release := buildAsRelease(t, previousVersion)
	if got := versionOf(t, release); got != rollbackVersion {
		t.Fatalf("this checkout built as a release calls itself %q", got)
	}
	for name, prepare := range compatDatabases(t) {
		t.Run(name, func(t *testing.T) {
			for _, f := range []string{upgrade.StatusFile, upgrade.HistoryFile, "previous-gateon", "lock"} {
				_ = os.Remove(filepath.Join(state, f))
			}
			env := SetupTestEnv(t)
			prepare(t, env)
			startCompatBackend(t, env.Ports["mock_backend"])
			svc := &processService{t: t, env: env, binary: filepath.Join(env.Dir, "installed", "gateon")}

			// The last release, installed and serving.
			copyBinary(t, previous, svc.binary)
			svc.start()
			svc.running.waitReady(env.Ports["mgmt"])
			requireProxied(t, "the last release", env.Ports["http_plain"])
			before := appliedMigrations(t, env)

			// The upgrade, as the last release's helper leaves it: its binary
			// kept, this build in place, and the outcome on record.
			copyBinary(t, svc.binary, filepath.Join(state, "previous-gateon"))
			copyBinary(t, release, svc.binary)
			done := upgrade.Status{
				Phase: upgrade.PhaseSucceeded, Target: rollbackVersion, Previous: previousVersion,
				RequestedBy: "compat", StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(),
			}
			writeHelperState(t, state, done)
			if err := svc.Restart(t.Context()); err != nil {
				t.Fatal(err)
			}
			svc.running.waitReady(env.Ports["mgmt"])
			requireProxied(t, "this build", env.Ports["http_plain"])
			after := appliedMigrations(t, env)
			t.Logf("migrations applied: %d by %s, %d after this build", before, previousVersion, after)

			st, err := helper.Rollback(t.Context(), helper.Config{
				Version: rollbackVersion, BinaryPath: svc.binary, DataDir: env.Dir, StateDir: state,
				Service: svc, Arch: runtime.GOARCH, ReadyTimeout: compatReadyTimeout, Logf: t.Logf,
			}, helper.RollbackOptions{To: previousVersion, RequestedBy: "compat"})
			if err != nil {
				t.Fatalf("the helper could not run: %v", err)
			}
			if st.Phase != upgrade.PhaseRolledBack || st.Reason != upgrade.ReasonRequested {
				t.Fatalf("the rollback ended %s/%q: %s did not answer the helper, or was not asked", st.Phase, st.Reason, previousVersion)
			}
			if st.RestoreDatabase {
				t.Fatal("a rollback one release back put a database copy back; it must lose nothing written since the upgrade")
			}
			sameFile(t, svc.binary, previous)
			svc.running.waitReady(env.Ports["mgmt"])
			requireProxied(t, "the last release, put back", env.Ports["http_plain"])
			if got := appliedMigrations(t, env); got != after {
				t.Fatalf("the database holds %d applied migrations after the rollback and held %d before it", got, after)
			}
			if _, ok := upgrade.Kept(state, previousVersion); ok {
				t.Fatal("a second rollback is on offer, to the release that is already running")
			}
			svc.running.stop()
		})
	}
}

func writeHelperState(t *testing.T, state string, st upgrade.Status) {
	t.Helper()
	root, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := upgrade.WriteJSON(root, upgrade.StatusFile, st, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := upgrade.WriteJSON(root, upgrade.HistoryFile, []upgrade.Status{st}, 0o644); err != nil {
		t.Fatal(err)
	}
}

func sameFile(t *testing.T, a, b string) {
	t.Helper()
	x, err := os.ReadFile(a) // #nosec G304 -- a path under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	y, err := os.ReadFile(b) // #nosec G304 -- the binary the test was given
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x, y) {
		t.Fatalf("%s is not the last release's binary", a)
	}
}
