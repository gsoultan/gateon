// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package upgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/selfupdate"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The phases and reasons only the gateway's half produces: an install that
// has not reached the helper yet, or never did.
const (
	PhaseDownloading Phase = "downloading"
	PhaseRequested   Phase = "requested"

	// ReasonDownload: the release could not be fetched.
	ReasonDownload Reason = "download"
	// ReasonHelper: the helper never picked the request up.
	ReasonHelper Reason = "helper"
)

// Blocker is why this gateway cannot install a release itself.
type Blocker uint8

const (
	BlockerNone Blocker = iota
	// BlockerOrchestrated: a container, a pod or a hand-started binary.
	BlockerOrchestrated
	// BlockerNoHelper: a systemd service without the helper's units.
	BlockerNoHelper
	// BlockerNoKey: this build can verify nothing.
	BlockerNoKey
	// BlockerDevBuild: not a release, so nothing is newer than it.
	BlockerDevBuild
)

// The refusals of Install.
var (
	// ErrBlocked wraps a refusal for a Blocker.
	ErrBlocked = errors.New("this gateway cannot install a release itself")
	// ErrNotOffered is a version other than the newest verified release.
	ErrNotOffered = errors.New("that is not the release the last check found")
	// ErrBusy is an install requested while one is running.
	ErrBusy = errors.New("an upgrade is already in progress")
)

// The pacing of the gateway's half.
const (
	// stageTimeout bounds one download and verification.
	stageTimeout = 15 * time.Minute
	// helperGrace is how long a request may wait for the helper before the
	// install is reported as never picked up.
	helperGrace = 90 * time.Second
	// staleAfter is how old an unfinished helper status must be before a new
	// install may start over it: a helper that died mid-install leaves one.
	staleAfter = 30 * time.Minute
	// autoEvery is how often the automatic-install policy is evaluated. It
	// reads what the last check found and asks no server.
	autoEvery = 5 * time.Minute
	// autoBackoff spaces automatic attempts after one that did not reach
	// the helper, so an unreachable mirror is not asked every five minutes
	// of the window.
	autoBackoff = time.Hour
)

// Checker is what the installer needs of the release check.
type Checker interface {
	Status() selfupdate.Status
}

// stager is Stager.Stage; tests supply their own.
type stager interface {
	Stage(ctx context.Context, source string, req Request) error
}

// Options is what an Installer is built from.
type Options struct {
	// Version is the running release.
	Version  string
	DataDir  string
	StateDir string
	Checker  Checker
	// Config returns the saved settings each time it is asked.
	Config func() *gateonv1.UpdateConfig
	Stager stager
	// HasKey: this build carries a release key.
	HasKey bool
	// HelperEnabled reports whether the unit that starts the helper is
	// enabled. Nil asks systemd's own record of it.
	HelperEnabled func() bool
	Now           func() time.Time
}

// Installer is the gateway's half of an install: it decides whether one may
// start, runs the download, and reports where it stands. It is safe for
// concurrent use. Run must be running for an install to make progress.
type Installer struct {
	opts      Options
	current   selfupdate.Version
	isRelease bool
	jobs      chan Request

	mu    sync.Mutex
	local *Status // the install this process started, until the helper owns it
	// requestedAt is when the request was left for the helper.
	requestedAt time.Time
	autoAfter   time.Time
}

// NewInstaller builds an Installer.
func NewInstaller(opts Options) *Installer {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.HelperEnabled == nil {
		opts.HelperEnabled = helperEnabled
	}
	v, ok := selfupdate.ParseVersion(opts.Version)
	return &Installer{opts: opts, current: v, isRelease: ok, jobs: make(chan Request, 1)}
}

// Blocker reports why this gateway cannot install, or BlockerNone.
func (i *Installer) Blocker() Blocker {
	switch {
	case i.opts.Checker.Status().InstallKind != selfupdate.InstallSystemd:
		return BlockerOrchestrated
	case !i.isRelease:
		return BlockerDevBuild
	case !i.opts.HasKey:
		return BlockerNoKey
	case !i.opts.HelperEnabled():
		return BlockerNoHelper
	}
	return BlockerNone
}

// helperWanted is the link `systemctl enable gateon-upgrade.path` makes.
// Reading it is how an unprivileged gateway learns the watcher is enabled
// without asking systemd, which it may not be allowed to.
const helperWanted = "/etc/systemd/system/multi-user.target.wants/gateon-upgrade.path"

func helperEnabled() bool {
	_, err := os.Lstat(helperWanted)
	return err == nil
}

// Install starts installing version, which must be the newest release the
// last check verified. It returns once the install is queued; View reports
// what becomes of it.
func (i *Installer) Install(version, by string, automatic bool) error {
	if i.Blocker() != BlockerNone {
		return ErrBlocked
	}
	st := i.opts.Checker.Status()
	v, ok := selfupdate.ParseVersion(version)
	if !ok || !st.UpdateAvailable || st.Latest != v.String() || st.Signature != selfupdate.SignatureVerified {
		return ErrNotOffered
	}
	now := i.opts.Now().UTC()
	req := Request{Version: v.String(), RequestedBy: SanitizeRequestedBy(by), Automatic: automatic, RequestedAt: now}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.busyLocked(now) {
		return ErrBusy
	}
	select {
	case i.jobs <- req:
	default:
		return ErrBusy
	}
	i.local = &Status{
		Phase: PhaseDownloading, Target: req.Version, Previous: i.opts.Version,
		RequestedBy: req.RequestedBy, Automatic: automatic, StartedAt: now,
	}
	logger.L.LogInfo("installing a gateon release", "running", i.opts.Version, "target", req.Version,
		"requested_by", req.RequestedBy, "automatic", automatic)
	return nil
}

// busyLocked reports whether an install is under way, here or in the helper.
func (i *Installer) busyLocked(now time.Time) bool {
	if i.local != nil && !i.local.Phase.Finished() {
		return true
	}
	helper, _ := i.readState()
	return helper != nil && !helper.Phase.Finished() && now.Sub(helper.StartedAt) < staleAfter
}

// Run performs queued installs and evaluates the automatic-install policy,
// until ctx is done.
func (i *Installer) Run(ctx context.Context) {
	ticker := time.NewTicker(autoEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-i.jobs:
			i.stage(ctx, req)
		case <-ticker.C:
			i.auto()
		}
	}
}

// stage downloads and verifies the release and leaves the request.
func (i *Installer) stage(ctx context.Context, req Request) {
	ctx, cancel := context.WithTimeout(ctx, stageTimeout)
	defer cancel()
	err := i.opts.Stager.Stage(ctx, i.opts.Checker.Status().Source, req)
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.local == nil {
		return
	}
	if err == nil {
		i.local.Phase, i.requestedAt = PhaseRequested, i.opts.Now()
		return
	}
	logger.L.LogWarn("the release was not handed to the upgrade helper", "target", req.Version, "error", err)
	i.failLocked(stageReason(err))
}

func (i *Installer) failLocked(reason Reason) {
	i.local.Phase, i.local.Reason = PhaseRefused, reason
	i.local.FinishedAt = i.opts.Now().UTC()
	i.autoAfter = i.local.FinishedAt.Add(autoBackoff)
}

func stageReason(err error) Reason {
	switch {
	case errors.Is(err, selfupdate.ErrNoKey):
		return ReasonNoKey
	case errors.Is(err, selfupdate.ErrSignature):
		return ReasonSignature
	case errors.Is(err, ErrChecksum):
		return ReasonChecksum
	case errors.Is(err, selfupdate.ErrMalformed):
		return ReasonMalformed
	default:
		return ReasonDownload
	}
}

// auto installs the newest release when the policy says this is the time.
func (i *Installer) auto() {
	policy := AutoSettings(i.opts.Config())
	st := i.opts.Checker.Status()
	latest, ok := selfupdate.ParseVersion(st.Latest)
	now := i.opts.Now()
	if !policy.Enabled || !ok || !st.UpdateAvailable || !policy.Scope.Allows(i.current, latest) || !policy.Window.Contains(now.Local()) {
		return
	}
	i.mu.Lock()
	wait := now.Before(i.autoAfter)
	i.mu.Unlock()
	if wait || i.failedBefore(latest.String()) {
		return
	}
	if err := i.Install(latest.String(), "", true); err != nil && !errors.Is(err, ErrBusy) {
		logger.L.LogDebug("an automatic install did not start", "target", latest.String(), "error", err)
	}
}

// failedBefore reports whether the helper already tried version and did not
// succeed. An automatic install is not repeated night after night into the
// same rollback; an administrator can still ask for it by hand.
func (i *Installer) failedBefore(version string) bool {
	_, history := i.readState()
	for _, h := range history {
		if h.Target == version && h.Phase != PhaseSucceeded {
			return true
		}
	}
	return false
}

// readState reads the helper's status and history. Both are absent until
// the helper has run once.
func (i *Installer) readState() (*Status, []Status) {
	root, err := os.OpenRoot(i.opts.StateDir)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = root.Close() }()
	var history []Status
	if err := ReadJSON(root, HistoryFile, &history); err != nil {
		history = nil
	}
	var st Status
	if err := ReadJSON(root, StatusFile, &st); err != nil {
		return nil, history
	}
	return &st, history
}

// View is what the dashboard is shown.
type View struct {
	Blocker Blocker
	// Current is the install in hand or the last one; nil when none.
	Current *Status
	History []Status
	Auto    Auto
}

// View reports where installing stands.
func (i *Installer) View() View {
	helper, history := i.readState()
	i.mu.Lock()
	defer i.mu.Unlock()
	return View{
		Blocker: i.Blocker(),
		Current: i.currentLocked(helper),
		History: history,
		Auto:    AutoSettings(i.opts.Config()),
	}
}

// currentLocked chooses between the install this process started and the
// helper's account. The helper's wins once it has picked the request up.
func (i *Installer) currentLocked(helper *Status) *Status {
	if i.local == nil {
		return helper
	}
	if helper != nil && helper.Target == i.local.Target && !helper.StartedAt.Before(i.local.StartedAt) {
		i.local = nil
		return helper
	}
	if i.local.Phase == PhaseRequested && i.opts.Now().Sub(i.requestedAt) > helperGrace {
		i.abandonLocked()
	}
	local := *i.local
	return &local
}

// abandonLocked withdraws a request the helper never took, so that enabling
// the helper next week does not install a release nobody is waiting for.
func (i *Installer) abandonLocked() {
	_ = os.Remove(filepath.Join(i.opts.DataDir, SpoolName, RequestFile))
	i.failLocked(ReasonHelper)
}
