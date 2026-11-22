// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
)

// replacedFile is the binary a rollback replaced, kept while the helper
// waits for the previous one: the way back when that one does not come up.
const replacedFile = "replaced-gateon"

// RollbackOptions is what a rollback is asked.
type RollbackOptions struct {
	// To is the release the asker was shown. The helper refuses when it kept
	// another one. Empty accepts whichever it kept.
	To          string
	RequestedBy string
	// RestoreDatabase puts back the copies taken before the installed release
	// migrated, discarding what was written since. Only `gateon upgrade
	// --rollback` at a root shell sets it; a request file cannot.
	RestoreDatabase bool
}

// Rollback puts back the release the last upgrade replaced, on an operator's
// word rather than because a gateway failed to start (ADR 0105). It returns
// the outcome, which it has also written to the state directory.
func Rollback(ctx context.Context, cfg Config, opts RollbackOptions) (upgrade.Status, error) {
	cfg.defaults()
	r, release, err := open(cfg)
	if err != nil {
		return upgrade.Status{}, err
	}
	defer release()
	return r.rollback(ctx, opts), nil
}

// history is the helper's record of finished installs, newest first.
func (r *run) history() []upgrade.Status {
	var history []upgrade.Status
	if err := upgrade.ReadJSON(r.state, upgrade.HistoryFile, &history); err != nil && !errors.Is(err, os.ErrNotExist) {
		r.cfg.Logf("the upgrade history could not be read and is started again: %v", err)
		return nil
	}
	return history
}

// kept reports whether the binary of the previous release is still there.
func (r *run) kept() bool {
	info, err := r.state.Lstat(previousFile)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

// rollback is one rollback on request.
//
// The status it writes while it waits is read by the previous release, which
// refuses a file with a field it does not know. So it carries only what the
// first release with a helper knew: no field added since is set here, and
// TestTheRollbackStatusIsReadableByTheFirstHelperRelease holds it to that.
func (r *run) rollback(ctx context.Context, opts RollbackOptions) upgrade.Status {
	previous, ok := upgrade.PreviousOf(r.history(), r.cfg.Version)
	r.status = upgrade.Status{
		Reason:      upgrade.ReasonRequested,
		Target:      r.cfg.Version,
		Previous:    previous,
		RequestedBy: upgrade.SanitizeRequestedBy(opts.RequestedBy),
		StartedAt:   r.cfg.Now().UTC(),
	}
	if !ok || !r.kept() || (opts.To != "" && !upgrade.SameRelease(opts.To, previous)) {
		return r.finish(upgrade.PhaseRefused, upgrade.ReasonNoPrevious, nil)
	}
	restore, err := r.restoreOnRollback(opts)
	if err != nil {
		return r.finish(upgrade.PhaseRefused, upgrade.ReasonNeedsRestore, err)
	}
	replaced := filepath.Join(r.cfg.StateDir, replacedFile)
	if err := copyFile(r.cfg.BinaryPath, replaced, binaryMode); err != nil {
		return r.finish(upgrade.PhaseRefused, upgrade.ReasonInstall, fmt.Errorf("keep the installed binary: %w", err))
	}
	defer func() { _ = os.Remove(replaced) }()
	r.status.RestoreDatabase = restore
	r.expect(upgrade.PhaseRollingBack, previous)
	if err := copyFile(filepath.Join(r.cfg.StateDir, previousFile), r.cfg.BinaryPath, binaryMode); err != nil {
		// Nothing was replaced and nothing was restarted.
		r.status.RestoreDatabase = false
		return r.finish(upgrade.PhaseRefused, upgrade.ReasonInstall, fmt.Errorf("put the previous binary back: %w", err))
	}
	r.restart(ctx)
	if r.waitReady(ctx) {
		return r.finish(upgrade.PhaseRolledBack, upgrade.ReasonRequested, nil)
	}
	return r.forward(ctx, replaced)
}

// restoreOnRollback decides what becomes of the database, from what the
// installed release said it did to it.
//
// A release built compatible with the previous one only added to the schema
// (ADR 0102), so the previous one runs on the database as it is and nothing
// written since the upgrade is lost. That is the rollback a gateway may ask
// for. Anything else needs the copy taken before the migration put back,
// which discards what was written since, and only a root shell may say so.
func (r *run) restoreOnRollback(opts RollbackOptions) (restore bool, err error) {
	mig := r.migration()
	switch {
	case !mig.ran:
		return false, nil
	case opts.RestoreDatabase && mig.restorable:
		return true, nil
	case opts.RestoreDatabase:
		return false, errors.New("the installed release migrated a database it took no copy of")
	case mig.compatible:
		return false, nil
	}
	return false, errors.New("the installed release migrated a database the previous one was not tested on")
}

// forward answers a previous release that did not come up: the release that
// was running is put back, so that asking for a rollback never leaves a host
// worse off than not asking.
func (r *run) forward(ctx context.Context, replaced string) upgrade.Status {
	r.cfg.Logf("the previous gateway (%s) did not report ready; putting %s back", r.status.Previous, r.status.Target)
	r.status.RestoreDatabase = false
	r.expect(upgrade.PhaseRestarting, r.status.Target)
	if err := copyFile(replaced, r.cfg.BinaryPath, binaryMode); err != nil {
		return r.finish(upgrade.PhaseFailed, upgrade.ReasonInstall, fmt.Errorf("put the replaced binary back: %w", err))
	}
	r.restart(ctx)
	if !r.waitReady(ctx) {
		r.cfg.Logf("gateon %s is back in place and has not reported ready", r.status.Target)
	}
	return r.finish(upgrade.PhaseFailed, upgrade.ReasonPreviousNotReady, nil)
}
