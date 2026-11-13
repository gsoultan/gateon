// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package install

import (
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
)

// directives is a unit without its comments and blank lines, so the unit
// `gateon install` writes and the one a package ships can be compared.
func directives(unit string) []string {
	var out []string
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// TestThePackagedUpgradeUnitsAreTheOnesTheInstallerWrites: two copies of a
// unit that runs as root drift apart silently; a package would then ship a
// helper confined differently from the one the tests in this package read.
func TestThePackagedUpgradeUnitsAreTheOnesTheInstallerWrites(t *testing.T) {
	t.Parallel()

	pairs := map[string][2]string{
		upgradePathUnit:    {renderUpgradePathUnit(), repoFile(t, "packaging", upgradePathUnit)},
		upgradeServiceUnit: {renderUpgradeServiceUnit("/usr/bin/gateon"), repoFile(t, "packaging", upgradeServiceUnit)},
	}
	for name, pair := range pairs {
		rendered, packaged := directives(pair[0]), directives(pair[1])
		if !slices.Equal(rendered, packaged) {
			t.Errorf("%s: gateon install writes\n%s\nand the packages ship\n%s",
				name, strings.Join(rendered, "\n"), strings.Join(packaged, "\n"))
		}
		for _, bad := range []string{"%!", "MISSING", "EXTRA", "%s"} {
			if strings.Contains(pair[0], bad) {
				t.Errorf("%s: the rendered unit contains %q", name, bad)
			}
		}
	}
}

// TestTheWatcherWatchesTheFileTheGatewayWrites: the path unit and the
// gateway agree on one file name by nothing but this test. Were they to
// differ, "Upgrade now" would wait for a helper that never starts.
func TestTheWatcherWatchesTheFileTheGatewayWrites(t *testing.T) {
	t.Parallel()

	want := "PathExists=" + path.Join(stateDir, upgrade.SpoolName, upgrade.RequestFile)
	for name, unit := range map[string]string{
		"the unit gateon install writes": renderUpgradePathUnit(),
		"packaging/" + upgradePathUnit:   repoFile(t, "packaging", upgradePathUnit),
	} {
		if !slices.Contains(directives(unit), want) {
			t.Errorf("%s does not have %q:\n%s", name, want, unit)
		}
		if !slices.Contains(directives(unit), "Unit="+upgradeServiceUnit) {
			t.Errorf("%s does not start %s", name, upgradeServiceUnit)
		}
	}
}

// TestTheHelperUnitCanDoItsWorkAndLittleElse holds the directives the
// helper depends on, and the ones that confine a process running as root.
func TestTheHelperUnitCanDoItsWorkAndLittleElse(t *testing.T) {
	t.Parallel()

	unit := directives(renderUpgradeServiceUnit("/opt/gateon/bin/gateon"))
	for _, want := range []string{
		"Type=oneshot",
		"ExecStart=/opt/gateon/bin/gateon upgrade-helper --data-dir " + stateDir,
		// The helper renames over the binary, so it writes the directory
		// holding it; and it removes the request from the gateway's.
		"ReadWritePaths=/opt/gateon/bin -" + stateDir,
		// Where the helper keeps its status; the gateway reads it there.
		"StateDirectory=" + path.Base(upgrade.DefaultStateDir),
		"StateDirectoryMode=0755",
		// The default start timeout kills a oneshot after 90 seconds.
		"TimeoutStartSec=45min",
		"EnvironmentFile=-/etc/default/gateon",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ProtectHome=true",
		"PrivateTmp=true",
		"PrivateDevices=true",
		// The helper downloads nothing: what it installs is already on disk.
		"PrivateNetwork=true",
		"RestrictAddressFamilies=AF_UNIX",
		"RestrictSUIDSGID=true",
		"SystemCallArchitectures=native",
	} {
		if !slices.Contains(unit, want) {
			t.Errorf("the helper's unit is missing %q", want)
		}
	}
	for _, line := range unit {
		if strings.HasPrefix(line, "User=") || strings.HasPrefix(line, "WantedBy=") {
			t.Errorf("the helper's unit has %q: it runs as root, and only when the watcher starts it", line)
		}
	}
}

// TestThePackagesShipTheUpgradeUnits: a package without them installs a
// gateway whose dashboard offers an install nothing performs.
func TestThePackagesShipTheUpgradeUnits(t *testing.T) {
	t.Parallel()

	for _, file := range []string{".goreleaser.yaml", "nfpm.yaml"} {
		cfg := repoFile(t, file)
		for _, unit := range []string{upgradePathUnit, upgradeServiceUnit} {
			if !strings.Contains(cfg, "packaging/"+unit) || !strings.Contains(cfg, "/lib/systemd/system/"+unit) {
				t.Errorf("%s does not ship %s", file, unit)
			}
		}
	}
}

func watcherCalls(h *pkgHost) []string {
	var out []string
	for _, c := range h.calls() {
		if strings.Contains(c, upgradePathUnit) {
			out = append(out, c)
		}
	}
	return out
}

// TestOnlyAFirstInstallSwitchesSelfUpgradeOn: enabling the watcher lets the
// gateway's account ask root to replace the binary. A package upgrade must
// not switch that on for a host whose operator never had it, nor back on
// for one who disabled it.
func TestOnlyAFirstInstallSwitchesSelfUpgradeOn(t *testing.T) {
	for _, args := range [][]string{{"configure", ""}, {"1"}} {
		h := newPkgHost(t, false, false)
		h.run("preinstall.sh", "install")
		h.run("postinstall.sh", args...)
		if got := watcherCalls(h); !slices.Equal(got, []string{"enable --now " + upgradePathUnit}) {
			t.Errorf("postinstall %v on a fresh install: %q", args, got)
		}
	}

	deb := newPkgHost(t, true, true)
	deb.run("preinstall.sh", "upgrade", "1.8.2")
	deb.run("postinstall.sh", "configure", "1.8.2")
	rpm := newPkgHost(t, true, true)
	rpm.run("preinstall.sh", "2")
	rpm.run("postinstall.sh", "2")
	rpm.run("posttrans.sh")
	for name, h := range map[string]*pkgHost{"deb": deb, "rpm": rpm} {
		if got := watcherCalls(h); len(got) != 0 {
			t.Errorf("a %s upgrade touched the watcher: %q", name, got)
		}
	}
}

func TestRemovingThePackageSwitchesTheWatcherOff(t *testing.T) {
	for _, arg := range []string{"remove", "0"} {
		h := newPkgHost(t, true, true)
		h.run("postremove.sh", arg)
		if got := watcherCalls(h); !slices.Equal(got, []string{"disable --now " + upgradePathUnit}) {
			t.Errorf("postremove %s: %q", arg, got)
		}
	}
}
