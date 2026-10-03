// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// pkgHost runs the package scripts against stand-ins for systemctl and the
// commands that touch the real filesystem, recording every systemctl call.
type pkgHost struct {
	t       *testing.T
	bin     string
	log     string
	state   string
	enabled bool
	active  bool
}

func newPkgHost(t *testing.T, enabled, active bool) *pkgHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the package scripts are POSIX shell")
	}
	dir := t.TempDir()
	h := &pkgHost{t: t, bin: filepath.Join(dir, "bin"), log: filepath.Join(dir, "systemctl.log"),
		state: filepath.Join(dir, "upgrade.state"), enabled: enabled, active: active}
	if err := os.Mkdir(h.bin, 0o750); err != nil {
		t.Fatal(err)
	}
	h.shim("systemctl", `echo "$*" >> "$PKG_LOG"
case "$1" in
  is-enabled) [ "$FAKE_ENABLED" = yes ] ;;
  is-active) [ "$FAKE_ACTIVE" = yes ] ;;
esac`)
	for _, name := range []string{"getent", "useradd", "mkdir", "chown", "chmod"} {
		h.shim(name, "exit 0")
	}
	return h
}

func (h *pkgHost) shim(name, body string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil { // #nosec G306 -- an executable test stand-in
		h.t.Fatal(err)
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// run runs scripts/<script> with args, as dpkg or rpm would.
func (h *pkgHost) run(script string, args ...string) {
	h.t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join("..", "..", "scripts", script)}, args...)...) // #nosec G204 -- a tracked script
	cmd.Env = []string{
		"PATH=" + h.bin + ":/usr/bin:/bin",
		"PKG_LOG=" + h.log,
		"GATEON_UPGRADE_STATE=" + h.state,
		"FAKE_ENABLED=" + yesNo(h.enabled),
		"FAKE_ACTIVE=" + yesNo(h.active),
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		h.t.Fatalf("%s %v: %v\n%s", script, args, err, out)
	}
}

// calls is every systemctl call so far, one per line.
func (h *pkgHost) calls() []string {
	b, err := os.ReadFile(h.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// final is whether the service ends enabled and running, replaying calls.
func (h *pkgHost) final() (enabled, active bool) {
	enabled, active = h.enabled, h.active
	for _, c := range h.calls() {
		switch c {
		case "enable gateon":
			enabled = true
		case "disable gateon":
			enabled = false
		case "restart gateon", "start gateon":
			active = true
		case "stop gateon":
			active = false
		}
	}
	return enabled, active
}

// v100PostRemove is what the old package's postrm does on an upgrade, for
// both formats: v1.0.0's postremove.sh stopped and disabled unconditionally.
func (h *pkgHost) v100PostRemove() {
	h.t.Helper()
	f, err := os.OpenFile(h.log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		h.t.Fatal(err)
	}
	_, _ = f.WriteString("stop gateon\ndisable gateon\ndaemon-reload\n")
	_ = f.Close()
}

// TestADebUpgradeLeavesTheServiceAsTheOperatorHadIt: an operator disables
// gateon on a standby node; every upgrade enabled and restarted it (review
// F11). The deb order: new preinst, old postrm (v1.0.0's stops and disables),
// new postinst.
func TestADebUpgradeLeavesTheServiceAsTheOperatorHadIt(t *testing.T) {
	for _, tc := range []struct{ enabled, active bool }{{false, false}, {true, true}, {true, false}} {
		h := newPkgHost(t, tc.enabled, tc.active)
		h.run("preinstall.sh", "upgrade", "1.0.0")
		h.v100PostRemove()
		h.run("postinstall.sh", "configure", "1.0.0")
		if en, ac := h.final(); en != tc.enabled || ac != tc.active {
			t.Errorf("enabled=%v active=%v before a deb upgrade, enabled=%v active=%v after; calls %q",
				tc.enabled, tc.active, en, ac, h.calls())
		}
	}
}

// TestAnRpmUpgradeLeavesTheServiceAsTheOperatorHadIt: rpm runs the old
// package's %postun after the new %post, so posttrans has the last word.
func TestAnRpmUpgradeLeavesTheServiceAsTheOperatorHadIt(t *testing.T) {
	for _, tc := range []struct{ enabled, active bool }{{false, false}, {true, true}} {
		h := newPkgHost(t, tc.enabled, tc.active)
		h.run("preinstall.sh", "2")
		h.run("postinstall.sh", "2")
		h.v100PostRemove()
		h.run("posttrans.sh")
		if en, ac := h.final(); en != tc.enabled || ac != tc.active {
			t.Errorf("enabled=%v active=%v before an rpm upgrade, enabled=%v active=%v after; calls %q",
				tc.enabled, tc.active, en, ac, h.calls())
		}
		if _, err := os.Stat(h.state); !os.IsNotExist(err) {
			t.Error("posttrans left the upgrade state behind")
		}
	}
}

// TestAFreshInstallEnablesAndStarts: no upgrade, no recorded state -- as before.
func TestAFreshInstallEnablesAndStarts(t *testing.T) {
	for _, args := range [][]string{{"configure", ""}, {"1"}} {
		h := newPkgHost(t, false, false)
		h.run("preinstall.sh", "install")
		h.run("postinstall.sh", args...)
		if en, ac := h.final(); !en || !ac {
			t.Errorf("postinstall %v: a fresh install ends enabled=%v active=%v; calls %q", args, en, ac, h.calls())
		}
	}
}

// TestPostremoveStopsTheServiceOnlyOnRemoval: on an upgrade -- deb "upgrade",
// rpm 1 -- postremove must not touch the service.
func TestPostremoveStopsTheServiceOnlyOnRemoval(t *testing.T) {
	for _, arg := range []string{"upgrade", "1"} {
		h := newPkgHost(t, true, true)
		h.run("postremove.sh", arg)
		if c := h.calls(); len(c) != 0 {
			t.Errorf("postremove %s (an upgrade) called systemctl: %q", arg, c)
		}
	}
	for _, arg := range []string{"remove", "purge", "0"} {
		h := newPkgHost(t, true, true)
		h.run("postremove.sh", arg)
		if en, ac := h.final(); en || ac {
			t.Errorf("postremove %s left the service enabled=%v active=%v", arg, en, ac)
		}
	}
}
