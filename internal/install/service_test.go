// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUnitHasNoUnfilledVerbs is the failure this template invites. Five
// positional verbs are filled by one Sprintf, and losing an argument does not
// error -- it writes %!s(MISSING) into the unit. Inside ReadWritePaths that
// produces a service which cannot write its own state, reported by systemd as a
// permissions problem rather than a malformed unit.
func TestUnitHasNoUnfilledVerbs(t *testing.T) {
	t.Parallel()

	unit := renderSystemdUnit("/usr/local/bin/gateon")

	for _, bad := range []string{"%!", "MISSING", "EXTRA", "%s"} {
		if strings.Contains(unit, bad) {
			t.Errorf("rendered unit contains %q, so an argument does not line up "+
				"with its verb:\n%s", bad, unit)
		}
	}
}

func TestUnitPointsAtTheBinaryAndItsDirectories(t *testing.T) {
	t.Parallel()

	unit := renderSystemdUnit("/opt/gateon/gateon")

	for _, want := range []string{
		"ExecStart=/opt/gateon/gateon",
		"WorkingDirectory=" + stateDir,
		"Environment=GLOBAL_CONFIG_FILE=" + configDir + "/global.json",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit is missing %q:\n%s", want, unit)
		}
	}
}

// TestUnitKeepsItsHardening pins the sandbox directives. Each one is load
// bearing, and dropping one is invisible: the service still starts, it is just
// no longer confined. ProtectSystem=strict in particular makes the whole
// filesystem read-only, so ReadWritePaths must name both directories or the
// gateway cannot persist config or state.
func TestUnitKeepsItsHardening(t *testing.T) {
	t.Parallel()

	unit := renderSystemdUnit("/usr/local/bin/gateon")

	for _, directive := range []string{
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ProtectHome=true",
		"PrivateTmp=true",
	} {
		if !strings.Contains(unit, directive) {
			t.Errorf("unit no longer sets %q; the service still starts, it is "+
				"just no longer confined:\n%s", directive, unit)
		}
	}

	if !strings.Contains(unit, "ReadWritePaths=-"+configDir+" -"+stateDir) {
		t.Errorf("ReadWritePaths does not name both %s and %s; with "+
			"ProtectSystem=strict the gateway cannot write what it needs:\n%s",
			configDir, stateDir, unit)
	}
}

func TestUnitRestartsOnFailure(t *testing.T) {
	t.Parallel()

	unit := renderSystemdUnit("/usr/local/bin/gateon")
	for _, want := range []string{"Restart=on-failure", "WantedBy=multi-user.target"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit is missing %q", want)
		}
	}
}

// TestUnitPathsAreAbsolute guards the constants themselves: systemd rejects a
// unit whose ExecStart or directory paths are relative, and the failure only
// shows up on the target machine at install time.
func TestUnitPathsAreAbsolute(t *testing.T) {
	t.Parallel()

	for name, path := range map[string]string{
		"configDir":       configDir,
		"stateDir":        stateDir,
		"systemdUnitPath": systemdUnitPath,
	} {
		if !strings.HasPrefix(path, "/") {
			t.Errorf("%s = %q, which systemd will reject as relative", name, path)
		}
	}
}

// TestSecureDirTightensAnExistingLooseDirectory is the case that matters on
// upgrade. MkdirAll succeeds silently when the directory already exists, so an
// /etc/gateon left at 0755 by an earlier install is tightened only by the
// chmod -- whose error used to be discarded, leaving global.json's database
// credentials, MaxMind key and SIEM tokens world-readable while install
// reported success.
func TestSecureDirTightensAnExistingLooseDirectory(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "gateon")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := secureDir(dir, 0o750); err != nil {
		t.Fatalf("secureDir: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o750 {
		t.Errorf("mode = %#o, want %#o; the world bit is still set on a "+
			"directory holding database credentials", perm, 0o750)
	}
}

func TestSecureDirCreatesWithTheRequestedMode(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "state")
	if err := secureDir(dir, 0o700); err != nil {
		t.Fatalf("secureDir: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("mode = %#o, want %#o", perm, 0o700)
	}
}

// TestSecureDirReportsFailure proves the error is returned rather than
// discarded: a path whose parent is a file cannot be created, and the installer
// must say so instead of continuing to the next hardening step.
func TestSecureDirReportsFailure(t *testing.T) {
	t.Parallel()

	parent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := secureDir(filepath.Join(parent, "child"), 0o750); err == nil {
		t.Error("secureDir reported success for a directory it could not create")
	}
}

// TestSecureOwnerReachesEveryEntry covers the walk rather than the syscall. The
// chown it replaces was `_ = exec.Command("chown", "-R", ...).Run()`, so the
// property that was missing is not "the owner changed" -- it is that a failure
// anywhere under the directory reaches the caller instead of being dropped.
//
// Running as root is not required and not assumed: an unprivileged Lchown to
// uid 0 fails, which is exactly the error path this needs to see reported.
func TestSecureOwnerReachesEveryEntry(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "global.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := secureOwner(dir)

	if os.Geteuid() == 0 {
		if err != nil {
			t.Fatalf("secureOwner as root: %v", err)
		}
		return
	}
	// Unprivileged: the walk must surface the refusal, naming the path, rather
	// than returning nil the way the shelled-out version did.
	if err == nil {
		t.Fatal("secureOwner returned nil while unable to chown; the failure was swallowed")
	}
	if !strings.Contains(err.Error(), "chown") {
		t.Errorf("error = %v, want it to say what it could not do", err)
	}
	// Naming a path *inside* the directory is what proves the walk reported,
	// rather than the directory itself failing first and masking it. Which
	// entry it stops on is WalkDir's ordering, not this test's business.
	if !strings.Contains(err.Error(), dir+string(filepath.Separator)) {
		t.Errorf("error = %v, want it to name an entry inside %s", err, dir)
	}
}

// TestSecureOwnerReportsAMissingDirectory keeps a typo'd path from looking like
// a successful install.
func TestSecureOwnerReportsAMissingDirectory(t *testing.T) {
	err := secureOwner(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("secureOwner returned nil for a directory that is not there")
	}
}
