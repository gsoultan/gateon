// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package install

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const serviceName = "gateon"

// Install installs Gateon as a system service.
// On Linux: writes systemd unit, enables and starts the service.
// On Windows: creates a service via sc.
func Install() error {
	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine executable path: %w", err)
	}
	binPath, err = filepath.EvalSymlinks(binPath)
	if err != nil {
		return fmt.Errorf("could not resolve executable path: %w", err)
	}

	switch runtime.GOOS {
	case "linux":
		return installLinux(binPath)
	case "windows":
		return installWindows(binPath)
	default:
		return fmt.Errorf("service install is not supported on %s", runtime.GOOS)
	}
}

// Uninstall removes the Gateon system service.
func Uninstall() error {
	switch runtime.GOOS {
	case "linux":
		return uninstallLinux()
	case "windows":
		return uninstallWindows()
	default:
		return fmt.Errorf("service uninstall is not supported on %s", runtime.GOOS)
	}
}

func runCmd(cmd *exec.Cmd) error {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", cmd.String(), err)
	}
	return nil
}

const (
	systemdUnitPath = "/lib/systemd/system/gateon.service"
	configDir       = "/etc/gateon"
	stateDir        = "/var/lib/gateon"
)

// The modes the two directories must keep, shared by the installer, the unit
// it writes and the tests that hold the packaged unit and scripts to the same
// values. See installLinux for why each is what it is.
const (
	configDirMode os.FileMode = 0o750
	stateDirMode  os.FileMode = 0o700
)

const systemdUnitTemplate = `[Unit]
Description=Gateon - API Gateway and Reverse Proxy
Documentation=https://github.com/gateon/gateon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gateon
Group=gateon
ExecStart=%s
Restart=on-failure
RestartSec=5s
WorkingDirectory=%s
Environment=GLOBAL_CONFIG_FILE=%s/global.json

# State and config directories. systemd re-applies the *DirectoryMode on
# every start and defaults it to 0755, so without these the modes the
# installer sets last only until the service first runs.
StateDirectory=gateon
StateDirectoryMode=0700
ConfigurationDirectory=gateon
ConfigurationDirectoryMode=0750

# Its own account, holding only the capabilities it uses (ADR 0019):
# CAP_NET_BIND_SERVICE for entrypoints below 1024, and CAP_BPF with
# CAP_NET_ADMIN for eBPF (ADR 0018) -- CAP_NET_ADMIN also lets HA move the
# virtual IP. Ambient, so the process holds them without being root; the
# bounding set is the most it, or anything it runs, can ever have.
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_BPF CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_BPF CAP_NET_ADMIN
# Kernels before 5.11 charge BPF maps to RLIMIT_MEMLOCK, which a process that
# is not root cannot raise for itself.
LimitMEMLOCK=infinity

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=-%s -%s

[Install]
WantedBy=multi-user.target
`

func installLinux(binPath string) error {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return fmt.Errorf("run as root (sudo) to install: sudo gateon install")
	}

	content := renderSystemdUnit(binPath)
	// #nosec G306 -- systemd requires unit files to be world-readable; 0600
	// makes the unit unloadable. This is the documented mode, not a default
	// nobody thought about.
	if err := os.WriteFile(systemdUnitPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}

	uid, gid, err := ensureServiceUser()
	if err != nil {
		return err
	}

	// 0750: the directory holds global.json, which carries database
	// credentials, the MaxMind licence key and SIEM tokens. The unit runs as
	// the service account and the chown below gives the directory to it, so
	// nothing needs the world bit that 0755 was granting every local account.
	// #nosec G302 -- a directory, not a file: the execute bit is what makes it
	// traversable, so 0750 is the tight mode here.
	if err := secureDir(configDir, configDirMode); err != nil {
		return err
	}
	if err := secureOwner(configDir, uid, gid); err != nil {
		return err
	}

	// #nosec G302 -- 0700 on a directory is already the tightest useful mode;
	// the execute bit is what makes it traversable by its owner.
	if err := secureDir(stateDir, stateDirMode); err != nil {
		return err
	}
	if err := secureOwner(stateDir, uid, gid); err != nil {
		return err
	}

	if err := runCmd(exec.Command("systemctl", "daemon-reload")); err != nil {
		return err
	}
	if err := runCmd(exec.Command("systemctl", "enable", "gateon")); err != nil {
		return err
	}
	if err := runCmd(exec.Command("systemctl", "restart", "gateon")); err != nil {
		return err
	}

	fmt.Printf("Gateon installed as systemd service.\n")
	fmt.Printf("  Config dir: %s\n", configDir)
	fmt.Printf("  State dir:  %s\n", stateDir)
	fmt.Printf("  status: systemctl status gateon\n")
	fmt.Printf("  logs:   journalctl -u gateon -f\n")
	return nil
}

func uninstallLinux() error {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return fmt.Errorf("run as root (sudo) to uninstall: sudo gateon uninstall")
	}

	_ = exec.Command("systemctl", "stop", "gateon").Run()
	_ = exec.Command("systemctl", "disable", "gateon").Run()
	if err := runCmd(exec.Command("systemctl", "daemon-reload")); err != nil {
		return err
	}
	if err := os.Remove(systemdUnitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove systemd unit: %w", err)
	}
	fmt.Println("Gateon service uninstalled.")
	return nil
}

func installWindows(binPath string) error {
	// #nosec G204 -- binPath is os.Executable() resolved through EvalSymlinks,
	// i.e. this process's own path, not input. `gateon install` is an explicit
	// administrator action.
	cmd := exec.Command("sc", "create", serviceName, `binPath= "`+binPath+`"`, "start=", "auto")
	cmd.Stdout = nil
	cmd.Stderr = nil
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := string(out)
		if strings.Contains(msg, "1073") || strings.Contains(msg, "exists") {
			return fmt.Errorf("service already exists; run 'gateon uninstall' first")
		}
		if strings.Contains(msg, "Access is denied") || strings.Contains(msg, "740") {
			return fmt.Errorf("run as Administrator to install the service")
		}
		return fmt.Errorf("sc create: %w\n%s", err, msg)
	}
	fmt.Println("Gateon installed as Windows service.")
	fmt.Println("  Start: sc start gateon")
	fmt.Println("  Stop:  sc stop gateon")
	return nil
}

func uninstallWindows() error {
	_ = exec.Command("sc", "stop", serviceName).Run()
	cmd := exec.Command("sc", "delete", serviceName)
	cmd.Stdout = nil
	cmd.Stderr = nil
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := string(output)
		if strings.Contains(msg, "1060") || strings.Contains(msg, "does not exist") {
			fmt.Println("Gateon service was not installed.")
			return nil
		}
		if strings.Contains(msg, "Access is denied") {
			return fmt.Errorf("run as Administrator to uninstall the service")
		}
		return fmt.Errorf("sc delete: %w\n%s", err, msg)
	}
	fmt.Println("Gateon service uninstalled.")
	return nil
}

// renderSystemdUnit fills the unit template for a binary at binPath.
//
// Split out so the installer and its tests fill the template through the same
// call. The template takes five positional verbs, two of them inside
// ReadWritePaths, and a positional Sprintf that loses an argument does not fail
// -- it writes %!s(MISSING) into the unit. Landing that inside ProtectSystem's
// writable-path list produces a service that cannot write its own state, and
// systemd reports it as a permissions problem rather than a malformed unit.
func renderSystemdUnit(binPath string) string {
	return fmt.Sprintf(systemdUnitTemplate, binPath, stateDir, configDir, configDir, stateDir)
}

// secureDir creates dir if absent and forces it to mode, returning an error if
// it cannot.
//
// The chmod matters more than the mkdir and used to be the one whose error was
// discarded. MkdirAll succeeds silently on a directory that already exists, so
// an upgrade over an earlier install's 0755 /etc/gateon relied entirely on the
// chmod to remove the world bit -- and with `_ = os.Chmod(...)` a failure left
// global.json, which carries database credentials, the MaxMind licence key and
// SIEM tokens, readable by every local account while install reported success.
//
// An installer run under sudo by an administrator who can see the message is
// exactly the place to fail loudly instead.
func secureDir(dir string, mode os.FileMode) error {
	if err := os.MkdirAll(dir, mode); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		return fmt.Errorf("secure %s to %#o: %w", dir, mode, err)
	}
	return nil
}

// secureOwner gives dir and everything under it to uid:gid -- the service
// account -- returning an error if it cannot.
//
// This is the other half of the argument in secureDir, and was the last piece
// still discarding its result: `_ = exec.Command("chown", "-R", "root:root",
// dir).Run()`. The mode alone is not enough on an upgrade. 0750 over a
// directory still owned by an unprivileged account leaves that account with rwx
// on global.json -- the database URL, the paseto signing secret, the MaxMind
// licence key -- while the unit it configures runs as another account. Losing the chown
// silently turns a permissions fix into a local privilege escalation, and the
// install prints "installed" either way.
//
// It also stops shelling out. exec.Command("chown", ...) resolves through PATH,
// so on a minimal image without coreutils the command simply does not exist,
// and with the error discarded that failure was indistinguishable from success.
// os.Lchown is a syscall: it cannot be missing, and it does not follow a symlink
// planted inside the tree.
func secureOwner(dir string, uid, gid int) error {
	// The traversal is scoped to an os.Root rather than done with
	// filepath.WalkDir over absolute paths. Walking and then acting on a path
	// is two operations on a name, and the thing the name refers to can change
	// in between; os.Root resolves every step inside the opened directory, so a
	// symlink planted mid-install cannot redirect a chown out of the tree. That
	// this runs as root during an install is exactly why it is worth scoping.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	if err := fs.WalkDir(root.FS(), ".", func(rel string, _ fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", filepath.Join(dir, rel), err)
		}
		if rel == "." {
			return nil
		}
		// Lchown, not Chown: a symlink in the tree should have its own
		// ownership changed, never its target's.
		if err := root.Lchown(rel, uid, gid); err != nil {
			return fmt.Errorf("chown %s to %d:%d: %w", filepath.Join(dir, rel), uid, gid, err)
		}
		return nil
	}); err != nil {
		return err
	}

	// The directory itself sits outside its own root, so it is done by name,
	// last: doing it first would mean a failure here masked anything the walk
	// would have reported, and a test could not tell the two apart.
	// dir is a package constant, not anything a caller supplies.
	if err := os.Lchown(dir, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", dir, uid, gid, err)
	}
	return nil
}

// serviceUser is the account the unit runs as. Not root: the gateway terminates
// hostile traffic, and nothing it does needs more than three capabilities.
const serviceUser = "gateon"

// ensureServiceUser creates the service account unless it exists, and returns
// its uid and gid.
func ensureServiceUser() (uid, gid int, err error) {
	if _, err := user.Lookup(serviceUser); err != nil {
		// #nosec G204 -- every argument is a constant or a fixed system path.
		if err := runCmd(exec.Command("useradd", useraddArgs(nologinShell())...)); err != nil {
			return 0, 0, fmt.Errorf("create the %s account: %w", serviceUser, err)
		}
	}
	u, err := user.Lookup(serviceUser)
	if err != nil {
		return 0, 0, fmt.Errorf("look up the %s account: %w", serviceUser, err)
	}
	return accountIDs(u)
}

// useraddArgs creates a system account with its own group, the state directory
// as its home but not created by useradd, and no login shell, because nobody
// logs in as it. The same flags as scripts/postinstall.sh.
func useraddArgs(shell string) []string {
	return []string{"--system", "--user-group", "--no-create-home",
		"--home-dir", stateDir, "--shell", shell, serviceUser}
}

// nologinShell is the first of the usual no-login shells this host has.
func nologinShell() string {
	for _, shell := range []string{"/usr/sbin/nologin", "/sbin/nologin"} {
		if _, err := os.Stat(shell); err == nil {
			return shell
		}
	}
	return "/bin/false"
}

func accountIDs(u *user.User) (uid, gid int, err error) {
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return 0, 0, fmt.Errorf("uid %q of %s: %w", u.Uid, u.Username, err)
	}
	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return 0, 0, fmt.Errorf("gid %q of %s: %w", u.Gid, u.Username, err)
	}
	return uid, gid, nil
}
