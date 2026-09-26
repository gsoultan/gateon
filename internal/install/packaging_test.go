// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package install

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// repoFile reads a file shipped from the repository root. go test runs in this
// package's directory, so the root is two levels up.
func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, parts...)...)
	b, err := os.ReadFile(path) // #nosec G304 -- test-time read of a tracked repository file
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// modeDirectives are the lines a unit needs so systemd keeps the modes the
// installer sets.
//
// StateDirectory= is not only "create this if missing". systemd.exec(5): the
// innermost directory "will have [its] access mode adjusted to what is
// specified in ... StateDirectoryMode=", which "Defaults to 0755" -- on every
// start. installLinux chmods /var/lib/gateon to 0700 and then restarts the
// service, and the unit it had just written put the directory back to 0755
// before gateon ran a single line, leaving the database beside it readable by
// every local account. ConfigurationDirectoryMode= is pinned for the case
// where systemd creates /etc/gateon itself, which would otherwise also be 0755.
func modeDirectives() []string {
	return []string{
		fmt.Sprintf("StateDirectoryMode=%04o", stateDirMode),
		fmt.Sprintf("ConfigurationDirectoryMode=%04o", configDirMode),
	}
}

func TestUnitKeepsTheDirectoryModesTheInstallerSets(t *testing.T) {
	t.Parallel()

	unit := renderSystemdUnit("/usr/local/bin/gateon")
	for _, want := range modeDirectives() {
		if !strings.Contains(unit, want) {
			t.Errorf("rendered unit is missing %q, so systemd resets the directory "+
				"to 0755 on every start:\n%s", want, unit)
		}
	}
}

// TestPackagedUnitKeepsTheDirectoryModes covers the unit the .deb and .rpm
// ship, which is a separate copy of the one above and was never tested.
func TestPackagedUnitKeepsTheDirectoryModes(t *testing.T) {
	t.Parallel()

	unit := repoFile(t, "packaging", "gateon.service")
	for _, want := range modeDirectives() {
		if !strings.Contains(unit, want) {
			t.Errorf("packaging/gateon.service is missing %q, so every deb/rpm "+
				"install runs with a 0755 directory", want)
		}
	}
}

// chmodLine matches `chmod <octal> <paths...>` in a shell script.
var chmodLine = regexp.MustCompile(`(?m)^\s*chmod\s+([0-7]{3,4})\s+(.+)$`)

// TestPostinstallAppliesTheInstallerModes is the upgrade half. The package's
// postinstall runs on every install and upgrade, and it chmodded /etc/gateon to
// 755 -- the exact mode `gateon install` refuses because the directory holds
// global.json, with the database credentials and the paseto secret that signs
// every admin session. An operator who tightened it by hand had it loosened
// again by the next upgrade.
func TestPostinstallAppliesTheInstallerModes(t *testing.T) {
	t.Parallel()

	script := repoFile(t, "scripts", "postinstall.sh")
	want := map[string]os.FileMode{configDir: configDirMode, stateDir: stateDirMode}
	seen := map[string]bool{}
	for _, m := range chmodLine.FindAllStringSubmatch(script, -1) {
		mode, err := strconv.ParseUint(m[1], 8, 32)
		if err != nil {
			t.Fatalf("unparseable chmod mode %q", m[1])
		}
		for _, dir := range strings.Fields(m[2]) {
			wantMode, ok := want[dir]
			if !ok {
				continue
			}
			seen[dir] = true
			if os.FileMode(mode) != wantMode {
				t.Errorf("postinstall.sh sets %s to %04o, want %04o (what gateon install sets)",
					dir, mode, wantMode)
			}
		}
	}
	for dir := range want {
		if !seen[dir] {
			t.Errorf("postinstall.sh never sets the mode of %s", dir)
		}
	}
}

// TestReleasePackageShipsTheConfigDirectoryPrivate checks the directory entry
// GoReleaser puts in the package itself, which is the mode /etc/gateon has
// between unpack and postinstall and what `dpkg --verify` compares against.
func TestReleasePackageShipsTheConfigDirectoryPrivate(t *testing.T) {
	t.Parallel()

	var cfg struct {
		Nfpms []struct {
			Contents []struct {
				Dst      string `yaml:"dst"`
				Type     string `yaml:"type"`
				FileInfo struct {
					Mode os.FileMode `yaml:"mode"`
				} `yaml:"file_info"`
			} `yaml:"contents"`
		} `yaml:"nfpms"`
	}
	if err := yaml.Unmarshal([]byte(repoFile(t, ".goreleaser.yaml")), &cfg); err != nil {
		t.Fatalf("parse .goreleaser.yaml: %v", err)
	}
	found := false
	for _, n := range cfg.Nfpms {
		for _, c := range n.Contents {
			if c.Dst != configDir || c.Type != "dir" {
				continue
			}
			found = true
			if c.FileInfo.Mode != configDirMode {
				t.Errorf(".goreleaser.yaml ships %s as %04o, want %04o", configDir, c.FileInfo.Mode, configDirMode)
			}
		}
	}
	if !found {
		t.Fatalf(".goreleaser.yaml has no directory entry for %s", configDir)
	}
}

// serviceCapabilities is every capability the unit may hold (ADR 0019).
var serviceCapabilities = []string{"CAP_NET_BIND_SERVICE", "CAP_BPF", "CAP_NET_ADMIN"}

// unitDirective returns the value of every `key=` line in unit.
func unitDirective(unit, key string) []string {
	var values []string
	for _, line := range strings.Split(unit, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), key+"="); ok {
			values = append(values, v)
		}
	}
	return values
}

// TestUnitsRunAsTheServiceAccount holds both units -- the one `gateon install`
// writes and the one the packages ship -- to the account and the capabilities.
// Either copy drifting back to User=root, or growing a capability, would undo
// ADR 0019 for everyone who installs that way, and nothing else would say so.
func TestUnitsRunAsTheServiceAccount(t *testing.T) {
	t.Parallel()

	units := map[string]string{
		"the unit gateon install writes": renderSystemdUnit("/usr/local/bin/gateon"),
		"packaging/gateon.service":       repoFile(t, "packaging", "gateon.service"),
	}
	for name, unit := range units {
		for _, key := range []string{"User", "Group"} {
			if got := unitDirective(unit, key); !slices.Equal(got, []string{serviceUser}) {
				t.Errorf("%s: %s=%q, want only %q", name, key, got, serviceUser)
			}
		}
		for _, key := range []string{"AmbientCapabilities", "CapabilityBoundingSet"} {
			got := unitDirective(unit, key)
			if len(got) != 1 {
				t.Errorf("%s: %d %s= lines, want exactly one", name, len(got), key)
				continue
			}
			caps := strings.Fields(got[0])
			slices.Sort(caps)
			want := slices.Sorted(slices.Values(serviceCapabilities))
			if !slices.Equal(caps, want) {
				t.Errorf("%s: %s=%s, want exactly %v", name, key, got[0], want)
			}
		}
	}
}

// TestPostinstallCreatesTheInstallersAccount: the package and `gateon install`
// create the same account and give it the same directories. On an upgrade the
// script is what moves an install that ran as root; it used to chown both
// directories to root:root on every upgrade.
func TestPostinstallCreatesTheInstallersAccount(t *testing.T) {
	t.Parallel()

	script := repoFile(t, "scripts", "postinstall.sh")
	want := "useradd " + strings.Join(useraddArgs(`"$shell"`), " ")
	if !strings.Contains(script, want) {
		t.Errorf("postinstall.sh does not create the account the way gateon install does; want\n  %s", want)
	}
	if !strings.Contains(script, "chown -R gateon:gateon /etc/gateon /var/lib/gateon") {
		t.Error("postinstall.sh does not give /etc/gateon and /var/lib/gateon to the service account")
	}
	if strings.Contains(script, "root:root") {
		t.Error("postinstall.sh still gives a directory to root:root, which locks the service out of it")
	}
}
