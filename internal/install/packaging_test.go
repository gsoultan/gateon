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

// serviceCapabilities is every capability the unit holds by default (ADR 0019,
// ADR 0049): CAP_NET_BIND_SERVICE alone. CAP_BPF and CAP_NET_ADMIN, which
// eBPF and HA's virtual IP need and nothing else does, are in the drop-in
// packaging/ebpf-ha.conf -- see TestTheEbpfDropInGrantsWhatEbpfAndHANeed.
var serviceCapabilities = []string{"CAP_NET_BIND_SERVICE"}

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

// dropInCapabilities is what packaging/ebpf-ha.conf adds: what loading and
// attaching the programs needs (internal/ebpf.missingCapabilities) and what
// HA's `ip addr` needs to move the virtual IP.
var dropInCapabilities = []string{"CAP_BPF", "CAP_NET_ADMIN"}

// TestTheEbpfDropInGrantsWhatEbpfAndHANeed: the unit stopped granting CAP_BPF
// and CAP_NET_ADMIN by default (review F8: a compromise of the proxy got
// interface, route and firewall control while eBPF and HA were both off). The
// drop-in that turns them back on must grant exactly those, raise the memlock
// limit old kernels charge BPF maps to, and allow bpf(2), which
// @system-service leaves out.
func TestTheEbpfDropInGrantsWhatEbpfAndHANeed(t *testing.T) {
	t.Parallel()

	dropIn := repoFile(t, "packaging", "ebpf-ha.conf")
	for _, key := range []string{"AmbientCapabilities", "CapabilityBoundingSet"} {
		got := unitDirective(dropIn, key)
		if len(got) != 1 {
			t.Fatalf("ebpf-ha.conf: %d %s= lines, want exactly one", len(got), key)
		}
		caps := strings.Fields(got[0])
		slices.Sort(caps)
		if want := slices.Sorted(slices.Values(dropInCapabilities)); !slices.Equal(caps, want) {
			t.Errorf("ebpf-ha.conf: %s=%s, want exactly %v", key, got[0], want)
		}
	}
	for _, want := range []string{"LimitMEMLOCK=infinity", "SystemCallFilter=bpf"} {
		if !strings.Contains(dropIn, want) {
			t.Errorf("ebpf-ha.conf is missing %q", want)
		}
	}
}

// hardening is the sandboxing both units carry (review F8). None of it is
// needed by the gateway; what eBPF and HA need on top is in the drop-in.
var hardening = []string{
	"NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true",
	"PrivateDevices=true", "ProtectKernelTunables=true", "ProtectKernelModules=true",
	"ProtectKernelLogs=true", "ProtectControlGroups=true", "ProtectClock=true", "ProtectHostname=true",
	"RestrictNamespaces=true", "RestrictRealtime=true", "RestrictSUIDSGID=true", "LockPersonality=true",
	"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", "SystemCallArchitectures=native",
	"SystemCallFilter=@system-service", "SystemCallErrorNumber=EPERM",
	// The ceiling gateon derives its Go soft limit from.
	"MemoryMax=90%",
	// Where GATEON_ENCRYPTION_KEY goes: a root-owned 0600 file, not an
	// Environment= line any local account can read with systemctl show.
	"EnvironmentFile=-/etc/default/gateon",
	"Environment=GATEON_DATA_DIR=",
}

func TestUnitsCarryTheHardening(t *testing.T) {
	t.Parallel()

	units := map[string]string{
		"the unit gateon install writes": renderSystemdUnit("/usr/local/bin/gateon"),
		"packaging/gateon.service":       repoFile(t, "packaging", "gateon.service"),
	}
	for name, unit := range units {
		for _, want := range hardening {
			if !strings.Contains(unit, want) {
				t.Errorf("%s is missing %q", name, want)
			}
		}
		if strings.Contains(unit, "%!") {
			t.Errorf("%s has a formatting error: %s", name, unit)
		}
		if strings.Contains(unit, "gateon/gateon") {
			t.Errorf("%s points its Documentation= at the wrong repository", name)
		}
		for _, line := range strings.Split(unit, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "Environment=") && strings.Contains(line, "ENCRYPTION_KEY") {
				t.Errorf("%s sets the encryption key in an Environment= line: %s", name, line)
			}
		}
	}
}

// TestThePackagesShipNoWindowsFileAndTheDropIn: the WinSW XML is a Windows
// service wrapper's config and was shipped into /etc/gateon as a Linux
// conffile (review F11); the eBPF/HA drop-in is what the unit now tells the
// operator to link.
func TestThePackagesShipNoWindowsFileAndTheDropIn(t *testing.T) {
	t.Parallel()

	for _, file := range []string{".goreleaser.yaml", "nfpm.yaml"} {
		cfg := repoFile(t, file)
		if strings.Contains(cfg, "gateon-service.xml") {
			t.Errorf("%s still ships the Windows service XML", file)
		}
		if !strings.Contains(cfg, "/usr/share/gateon/systemd/ebpf-ha.conf") {
			t.Errorf("%s does not ship the eBPF/HA drop-in", file)
		}
	}
}
