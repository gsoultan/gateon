// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package helper

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gsoultan/gateon/internal/selfupdate"
	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
)

// ServiceControl restarts the gateway's service.
type ServiceControl interface {
	// Restart stops the gateway and starts it again as one operation of the
	// service manager. One operation, not a stop and then a start: the
	// manager holds the gateway's listening sockets across a restart and
	// lets go of them when the service is stopped (ADR 0092).
	Restart(ctx context.Context) error
	// Restarts is how often the service manager has restarted the gateway
	// by itself since Restart, or 0 when that cannot be told.
	Restarts(ctx context.Context) int
}

// The pacing of the wait for a restarted gateway.
const (
	// DefaultReadyTimeout is how long a new binary has to report ready
	// before the old one is put back.
	DefaultReadyTimeout = 90 * time.Second
	// MinReadyTimeout and MaxReadyTimeout hold a configured timeout.
	MinReadyTimeout = 15 * time.Second
	MaxReadyTimeout = 15 * time.Minute
	// maxMigrationWait is the most a database backup and migration extend
	// the wait by. Copying a large SQLite file is slow and is not a failure;
	// it is also not allowed to hold the gateway down for ever.
	maxMigrationWait = 15 * time.Minute
	// crashLoopRestarts is how many restarts by the service manager are
	// taken to mean the new binary cannot start, without waiting out the
	// timeout while it is restarted again and again.
	crashLoopRestarts = 3
	defaultPoll       = 500 * time.Millisecond
)

// The helper's own files, beside the status and history upgrade names.
const (
	lockFile     = "lock"
	stagedFile   = "staged.tar.gz"
	previousFile = "previous-gateon"
	stateDirMode = 0o755
	// publicMode: the status and history are what the dashboard shows, and
	// the gateway reads them as another account.
	publicMode = 0o644
	binaryMode = 0o755
)

// ErrNoRequest is a run with nothing to do: no request in the spool.
var ErrNoRequest = errors.New("no upgrade was requested")

// ErrBusy is a second helper started while one is installing.
var ErrBusy = errors.New("another upgrade is in progress")

// Config is everything a run is told. None of it comes from the gateway.
type Config struct {
	// Version is the installed release: that of the binary running the helper.
	Version string
	// BinaryPath is the binary to replace.
	BinaryPath string
	// DataDir is the gateway's data directory, which holds the spool.
	DataDir string
	// ReleaseDir holds the request and the release when they are not in the
	// spool: `gateon upgrade` downloads into a directory of root's own.
	ReleaseDir string
	// StateDir is the helper's own directory.
	StateDir string
	Keys     []ed25519.PublicKey
	Service  ServiceControl
	// Arch is the architecture to install for.
	Arch         string
	ReadyTimeout time.Duration
	// AllowDowngrade installs a release that is not newer than Version. Only
	// `gateon upgrade` at a root shell sets it; a request file cannot.
	AllowDowngrade bool

	// Poll, Now and Sleep are for tests.
	Poll  time.Duration
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration)
	Logf  func(format string, args ...any)
}

func (c *Config) defaults() {
	if c.Poll <= 0 {
		c.Poll = defaultPoll
	}
	if c.ReadyTimeout <= 0 {
		c.ReadyTimeout = DefaultReadyTimeout
	}
	c.ReadyTimeout = min(max(c.ReadyTimeout, MinReadyTimeout), MaxReadyTimeout)
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = sleep
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// run is one install.
type run struct {
	cfg  Config
	data *os.Root // the gateway's data directory: untrusted
	// rel is where the request and the release are: data, under relPrefix,
	// unless Config.ReleaseDir names another directory.
	rel       *os.Root
	relPrefix string
	state     *os.Root // the helper's own
	status    upgrade.Status
}

// Run installs the release the spool holds a request for. It returns the
// outcome, which it has also written to the state directory; the error is
// for an install that could not even be accounted for.
func Run(ctx context.Context, cfg Config) (upgrade.Status, error) {
	cfg.defaults()
	r, release, err := open(cfg)
	if err != nil {
		return upgrade.Status{}, err
	}
	defer release()
	req, err := r.takeRequest()
	if err != nil {
		return upgrade.Status{}, err
	}
	r.begin(req)
	staged, err := r.stage()
	if err != nil {
		return r.finish(upgrade.PhaseRefused, reasonOf(err), err), nil
	}
	return r.install(ctx, staged), nil
}

// open takes the helper's lock and opens both directories.
func open(cfg Config) (*run, func(), error) {
	// #nosec G301 -- the status inside is read by the gateway's account.
	if err := os.MkdirAll(cfg.StateDir, stateDirMode); err != nil {
		return nil, nil, fmt.Errorf("create %s: %w", cfg.StateDir, err)
	}
	state, err := os.OpenRoot(cfg.StateDir)
	if err != nil {
		return nil, nil, err
	}
	lock, err := state.OpenFile(lockFile, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		_ = state.Close()
		return nil, nil, err
	}
	if err := lockExclusive(lock); err != nil {
		_, _ = lock.Close(), state.Close()
		return nil, nil, ErrBusy
	}
	r := &run{cfg: cfg, state: state}
	release := func() {
		for _, c := range []*os.Root{r.data, r.rel, state} {
			if c != nil {
				_ = c.Close()
			}
		}
		_ = lock.Close()
	}
	if r.data, err = os.OpenRoot(cfg.DataDir); err != nil {
		release()
		return nil, nil, fmt.Errorf("open the gateway's data directory: %w", err)
	}
	if cfg.ReleaseDir == "" {
		r.rel, r.relPrefix = r.data, upgrade.SpoolName
		return r, release, nil
	}
	if r.rel, err = os.OpenRoot(cfg.ReleaseDir); err != nil {
		release()
		return nil, nil, fmt.Errorf("open the release directory: %w", err)
	}
	return r, release, nil
}

// spool names a file the gateway writes about itself: its answer to the
// nonce and its migration record.
func spool(name string) string { return filepath.Join(upgrade.SpoolName, name) }

// release names a file of the release to install, beneath r.rel.
func (r *run) release(name string) string { return filepath.Join(r.relPrefix, name) }

// takeRequest reads the request and removes it, in that order and before
// anything else: the unit that starts the helper is triggered by the file
// existing, so a request that survived a failed run would be run again for
// ever.
func (r *run) takeRequest() (upgrade.Request, error) {
	var req upgrade.Request
	err := upgrade.ReadJSON(r.rel, r.release(upgrade.RequestFile), &req)
	if rmErr := r.rel.Remove(r.release(upgrade.RequestFile)); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return req, fmt.Errorf("remove the request: %w", rmErr)
	}
	if errors.Is(err, os.ErrNotExist) {
		return req, ErrNoRequest
	}
	if err != nil {
		return req, fmt.Errorf("read the request: %w", err)
	}
	return req, nil
}

func (r *run) begin(req upgrade.Request) {
	r.status = upgrade.Status{
		Phase:       upgrade.PhaseInstalling,
		Target:      req.Version,
		Previous:    r.cfg.Version,
		RequestedBy: upgrade.SanitizeRequestedBy(req.RequestedBy),
		Automatic:   req.Automatic,
		StartedAt:   r.cfg.Now().UTC(),
	}
	r.write()
}

// write stores the status. A status that cannot be written is logged and
// the install goes on: the binary matters more than the account of it.
func (r *run) write() {
	if err := upgrade.WriteJSON(r.state, upgrade.StatusFile, r.status, publicMode); err != nil {
		r.cfg.Logf("the upgrade status could not be written: %v", err)
	}
}

// reasonOf names why a release was refused.
func reasonOf(err error) upgrade.Reason {
	switch {
	case errors.Is(err, selfupdate.ErrNoKey):
		return upgrade.ReasonNoKey
	case errors.Is(err, selfupdate.ErrSignature):
		return upgrade.ReasonSignature
	case errors.Is(err, errChecksum):
		return upgrade.ReasonChecksum
	case errors.Is(err, errNotNewer):
		return upgrade.ReasonNotNewer
	case errors.Is(err, errInstall):
		return upgrade.ReasonInstall
	default:
		return upgrade.ReasonMalformed
	}
}

// finish records an outcome, in the status and in the history, and clears
// the spool of what the install no longer needs.
func (r *run) finish(phase upgrade.Phase, reason upgrade.Reason, cause error) upgrade.Status {
	r.status.Phase, r.status.Reason = phase, reason
	r.status.Expect, r.status.Nonce = "", ""
	r.status.FinishedAt = r.cfg.Now().UTC()
	r.write()
	r.remember()
	for _, name := range []string{upgrade.ChecksumsFile, upgrade.SignatureFile, r.archiveName()} {
		_ = r.rel.Remove(r.release(name))
	}
	_ = r.data.Remove(spool(upgrade.ReadyFile))
	_ = r.state.Remove(stagedFile)
	r.cfg.Logf("upgrade %s -> %s: %s (reason %q): %v", r.status.Previous, r.status.Target, phase, reason, cause)
	return r.status
}

// archiveName is the archive a request for the target would have brought,
// or a name nothing has when the target is not a version.
func (r *run) archiveName() string {
	v, ok := selfupdate.ParseVersion(r.status.Target)
	if !ok {
		return ".none"
	}
	return selfupdate.ArchiveName(v, r.cfg.Arch)
}

// remember appends the finished status to the history, newest first.
func (r *run) remember() {
	var history []upgrade.Status
	if err := upgrade.ReadJSON(r.state, upgrade.HistoryFile, &history); err != nil && !errors.Is(err, os.ErrNotExist) {
		r.cfg.Logf("the upgrade history could not be read and is started again: %v", err)
		history = nil
	}
	history = append([]upgrade.Status{r.status}, history...)
	if len(history) > upgrade.MaxHistory {
		history = history[:upgrade.MaxHistory]
	}
	if err := upgrade.WriteJSON(r.state, upgrade.HistoryFile, history, publicMode); err != nil {
		r.cfg.Logf("the upgrade history could not be written: %v", err)
	}
}
