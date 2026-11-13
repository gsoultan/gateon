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

// upgradeFlags is what `gateon upgrade` was asked.
type upgradeFlags struct {
	version, source, dataDir string
	downgrade, yes           bool
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
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(c.Err, "run as root to upgrade: sudo gateon upgrade")
		return exitUsage
	}
	if err := c.upgrade(ctx, f); err != nil {
		fmt.Fprintln(c.Err, "upgrade:", err)
		return exitFailed
	}
	return exitOK
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
	line, _ := bufio.NewReader(c.In).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
