// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package helper

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/selfupdate"
	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// EnvReadyTimeout overrides how long a new binary has to report ready: a Go
// duration, held between MinReadyTimeout and MaxReadyTimeout.
const EnvReadyTimeout = "GATEON_UPGRADE_READY_TIMEOUT"

// cliDir is where `gateon upgrade` downloads to, under the state directory:
// root's own, so nothing the gateway's account can write is in the path.
const cliDir = "cli"

// The exit codes of both commands.
const (
	exitOK = iota
	exitFailed
	exitUsage
)

// CLI is the terminal the commands talk to.
type CLI struct {
	Version string
	In      io.Reader
	Out     io.Writer
	Err     io.Writer
}

// readyTimeout is the profile's timeout unless EnvReadyTimeout names one.
func readyTimeout() time.Duration {
	def := config.CurrentTierDefaults().UpgradeReadyTimeout
	v := strings.TrimSpace(os.Getenv(EnvReadyTimeout))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// base is the configuration both commands share: this binary, replacing
// itself, on this machine.
func (c CLI) base(dataDir string) (Config, error) {
	bin, err := os.Executable()
	if err == nil {
		bin, err = filepath.EvalSymlinks(bin)
	}
	if err != nil {
		return Config{}, fmt.Errorf("find the installed binary: %w", err)
	}
	return Config{
		Version:      c.Version,
		BinaryPath:   bin,
		DataDir:      dataDir,
		StateDir:     upgrade.DefaultStateDir,
		Keys:         selfupdate.ReleaseKeys(),
		Service:      Systemd{Unit: GatewayUnit},
		Arch:         runtime.GOARCH,
		ReadyTimeout: readyTimeout(),
		Logf:         func(format string, args ...any) { fmt.Fprintf(c.Err, format+"\n", args...) },
	}, nil
}

// Helper is `gateon upgrade-helper`: what gateon-upgrade.service runs, as
// root, when the gateway leaves a request. It takes the gateway's data
// directory from the unit file and nothing from the gateway.
func (c CLI) Helper(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("upgrade-helper", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	dataDir := fs.String("data-dir", "/var/lib/gateon", "the gateway's data directory")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	cfg, err := c.base(*dataDir)
	if err != nil {
		fmt.Fprintln(c.Err, err)
		return exitFailed
	}
	st, err := Run(ctx, cfg)
	if errors.Is(err, ErrNoRequest) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(c.Err, err)
		return exitFailed
	}
	return c.report(st)
}

// report prints an outcome and turns it into an exit code.
func (c CLI) report(st upgrade.Status) int {
	if st.Reason.Requested() {
		return c.reportRollback(st)
	}
	switch st.Phase {
	case upgrade.PhaseSucceeded:
		fmt.Fprintf(c.Out, "gateon %s is installed and ready. The previous binary (%s) is kept.\n", st.Target, st.Previous)
		return exitOK
	case upgrade.PhaseRolledBack:
		fmt.Fprintf(c.Out, "gateon %s did not become ready; %s is back in place.\n", st.Target, st.Previous)
	case upgrade.PhaseRefused:
		fmt.Fprintf(c.Out, "gateon %s was not installed (%s). Nothing was changed.\n", st.Target, st.Reason)
	default:
		fmt.Fprintf(c.Out, "gateon %s is installed and did not become ready, and was not rolled back (%s): see doc/self-upgrade.md.\n",
			st.Target, st.Reason)
	}
	return exitFailed
}

// reportRollback prints how a rollback an operator asked for ended.
func (c CLI) reportRollback(st upgrade.Status) int {
	switch st.Reason {
	case upgrade.ReasonRequested:
		fmt.Fprintf(c.Out, "gateon %s is back in place and ready; %s was rolled back.\n", st.Previous, st.Target)
		if st.RestoreDatabase {
			fmt.Fprintln(c.Out, "The database copy taken before the upgrade was put back. What was written since is kept beside it as <database>.failed-upgrade.")
		}
		return exitOK
	case upgrade.ReasonNoPrevious:
		fmt.Fprintf(c.Out, "There is no previous release to roll gateon %s back to. Nothing was changed.\n", st.Target)
	case upgrade.ReasonNeedsRestore:
		fmt.Fprintf(c.Out, "gateon %s migrated a database that %s was not tested on. Nothing was changed.\n"+
			"Add --restore-database to put back the copy taken before the upgrade, or restore your own backup first: see doc/self-upgrade.md.\n",
			st.Target, st.Previous)
	case upgrade.ReasonPreviousNotReady:
		fmt.Fprintf(c.Out, "gateon %s did not become ready, so %s was put back and is installed: see `journalctl -u gateon`.\n", st.Previous, st.Target)
	}
	return exitFailed
}

// upgradeFlags is what `gateon upgrade` was asked.
type upgradeFlags struct {
	version, source, dataDir string
	downgrade, yes           bool
	rollback, restore        bool
}

// Upgrade is `gateon upgrade`: the same install an administrator starts
// from the dashboard, run by an operator who is already root. It needs no
// running gateway, which is the point: it is how a gateway that will not
// start is upgraded.
func (c CLI) Upgrade(ctx context.Context, args []string) int {
	var f upgradeFlags
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	fs.StringVar(&f.version, "version", "", "the release to install; the newest when empty")
	fs.StringVar(&f.source, "source", os.Getenv(selfupdate.EnvSource), "the release source; "+selfupdate.DefaultSource+" when empty")
	fs.StringVar(&f.dataDir, "data-dir", config.DataDir(), "the gateway's data directory")
	fs.BoolVar(&f.downgrade, "allow-downgrade", false, "install a release that is not newer than the installed one")
	fs.BoolVar(&f.yes, "yes", false, "do not ask for confirmation")
	fs.BoolVar(&f.rollback, "rollback", false, "put back the release the last upgrade replaced")
	fs.BoolVar(&f.restore, "restore-database", false,
		"with --rollback: put back the database copy taken before the upgrade, setting aside what was written since")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if msg := f.conflict(); msg != "" {
		fmt.Fprintln(c.Err, msg)
		return exitUsage
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(c.Err, "run as root to upgrade: sudo gateon upgrade")
		return exitUsage
	}
	run := c.upgrade
	if f.rollback {
		run = c.rollback
	}
	if err := run(ctx, f); err != nil {
		fmt.Fprintln(c.Err, "upgrade:", err)
		return exitFailed
	}
	return exitOK
}

// conflict names flags that cannot be meant together.
func (f upgradeFlags) conflict() string {
	switch {
	case f.restore && !f.rollback:
		return "--restore-database is for --rollback"
	case f.rollback && (f.version != "" || f.downgrade):
		return "--rollback puts back the release the last upgrade replaced; for any other release use --version with --allow-downgrade"
	}
	return ""
}

// rollback is `gateon upgrade --rollback`: the previous binary is already
// on the host, so nothing is downloaded and no release source is needed.
func (c CLI) rollback(ctx context.Context, f upgradeFlags) error {
	cfg, err := c.base(f.dataDir)
	if err != nil {
		return err
	}
	to, ok := upgrade.Kept(cfg.StateDir, c.Version)
	if !ok {
		return errors.New("there is no previous release to roll back to: the helper keeps the release the last upgrade replaced, until it is rolled back. " +
			"For another release use --version with --allow-downgrade")
	}
	if !f.yes && !c.confirmRollback(to, f.restore) {
		fmt.Fprintln(c.Out, "Nothing was changed.")
		return nil
	}
	fmt.Fprintf(c.Out, "Putting gateon %s back and restarting the gateway...\n", to)
	opts := RollbackOptions{To: to, RequestedBy: "root (gateon upgrade --rollback)", RestoreDatabase: f.restore}
	st, err := Rollback(ctx, cfg, opts)
	if err != nil {
		return err
	}
	if c.report(st) != exitOK {
		return errors.New("the rollback did not complete")
	}
	return nil
}

// confirmRollback asks before a restart, naming both releases and, when a
// database copy is to be put back, what that costs.
func (c CLI) confirmRollback(to string, restore bool) bool {
	fmt.Fprintf(c.Out, "Replace gateon %s with %s, the release installed before it, and restart the gateway?", c.Version, to)
	if restore {
		fmt.Fprint(c.Out, "\nThe database goes back to the copy taken before the upgrade. Everything written since is set aside as <database>.failed-upgrade.")
	}
	fmt.Fprint(c.Out, " [y/N] ")
	return c.yes()
}

func (c CLI) upgrade(ctx context.Context, f upgradeFlags) error {
	cfg, err := c.base(f.dataDir)
	if err != nil {
		return err
	}
	target, err := c.target(ctx, f)
	if err != nil || target == "" {
		return err
	}
	if !f.yes && !c.confirm(target) {
		fmt.Fprintln(c.Out, "Nothing was changed.")
		return nil
	}
	cfg.AllowDowngrade = f.downgrade
	cfg.ReleaseDir = filepath.Join(cfg.StateDir, cliDir, upgrade.SpoolName)
	stager := upgrade.Stager{
		DataDir: filepath.Join(cfg.StateDir, cliDir),
		Keys:    cfg.Keys,
		Fetch:   selfupdate.NewDownloader(c.Version),
		Arch:    cfg.Arch,
	}
	fmt.Fprintf(c.Out, "Downloading and verifying gateon %s...\n", target)
	req := upgrade.Request{Version: target, RequestedBy: "root (gateon upgrade)", RequestedAt: time.Now().UTC()}
	if err := stager.Stage(ctx, f.source, req); err != nil {
		return err
	}
	fmt.Fprintln(c.Out, "Installing and restarting the gateway...")
	st, err := Run(ctx, cfg)
	if err != nil {
		return err
	}
	if c.report(st) != exitOK {
		return errors.New("the upgrade did not complete")
	}
	return nil
}

// target is the release to install: the one asked for, or the newest the
// source lists. Empty with no error means there is nothing to do.
func (c CLI) target(ctx context.Context, f upgradeFlags) (string, error) {
	if f.version != "" {
		v, ok := selfupdate.ParseVersion(f.version)
		if !ok {
			return "", fmt.Errorf("%q is not a release version such as 1.8.3", f.version)
		}
		return v.String(), nil
	}
	checker := selfupdate.New(c.Version, func() *gateonv1.UpdateConfig {
		return &gateonv1.UpdateConfig{SourceUrl: f.source}
	})
	st := checker.Check(ctx)
	switch {
	case st.State != selfupdate.StateOK:
		return "", fmt.Errorf("the release source %s could not be read; see the line above", st.Source)
	case st.Signature != selfupdate.SignatureVerified:
		return "", selfupdate.ErrNoKey
	case !st.UpdateAvailable && !f.downgrade:
		fmt.Fprintf(c.Out, "gateon %s is installed and %s is the newest release. Nothing to do.\n", c.Version, st.Latest)
		return "", nil
	}
	return st.Latest, nil
}

// confirm asks before a restart, naming exactly what will be installed.
func (c CLI) confirm(target string) bool {
	fmt.Fprintf(c.Out, "Replace gateon %s with %s and restart the gateway? [y/N] ", c.Version, target)
	return c.yes()
}

func (c CLI) yes() bool {
	line, _ := bufio.NewReader(c.In).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
