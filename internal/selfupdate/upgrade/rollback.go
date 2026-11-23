// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package upgrade

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/selfupdate"
)

// ErrNoPrevious is a rollback asked for when the helper holds no release to
// go back to, or holds another one than the caller named.
var ErrNoPrevious = errors.New("there is no previous release to roll back to")

// ErrNeedsRestore is a rollback the gateway may not ask for: the previous
// release cannot run on the database as it is, and putting a copy back
// discards what was written since. That is decided at a root shell.
var ErrNeedsRestore = errors.New("rolling back needs the database copy put back; run `sudo gateon upgrade --rollback --restore-database` on the host")

// PreviousOf names the release the helper can put back over installed: the
// one the last upgrade replaced. The helper keeps one binary, so the answer
// is in the newest entry of its history that changed the installed binary.
//
// A refused entry changed nothing and is passed over. Anything else than an
// install of exactly the installed release ends the search: a rollback
// leaves the kept binary and the installed one the same, and an install the
// helper did not make (a package, a copy by hand) is one it kept nothing of.
func PreviousOf(history []Status, installed string) (string, bool) {
	for _, h := range history {
		if h.Phase == PhaseRefused {
			continue
		}
		stands := h.Phase == PhaseSucceeded || h.Phase == PhaseFailed
		if !stands || !SameRelease(h.Target, installed) || h.Previous == "" || SameRelease(h.Previous, installed) {
			return "", false
		}
		return h.Previous, true
	}
	return "", false
}

// Kept names the release the helper whose directory is stateDir can put
// back over installed.
func Kept(stateDir, installed string) (string, bool) {
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return "", false
	}
	defer func() { _ = root.Close() }()
	var history []Status
	if err := ReadJSON(root, HistoryFile, &history); err != nil {
		return "", false
	}
	return PreviousOf(history, installed)
}

// Rollback is what a gateway knows about going back a release.
type Rollback struct {
	// To is the release that would be put back; empty when there is none.
	To string
	// NeedsRestore: the installed release migrated a database To was not
	// tested on, so the gateway may not ask (see ErrNeedsRestore).
	NeedsRestore bool
}

// rollback reports what this gateway could be rolled back to.
func (i *Installer) rollback(history []Status) Rollback {
	if !i.helped() {
		return Rollback{}
	}
	to, ok := PreviousOf(history, i.opts.Version)
	if !ok {
		return Rollback{}
	}
	return Rollback{To: to, NeedsRestore: i.migratedPast(to)}
}

// helped reports whether a helper is there to be asked. A rollback needs no
// release key and no release build: it verifies nothing and downloads
// nothing, and root decides from its own record what goes back.
func (i *Installer) helped() bool {
	return i.opts.Checker.Status().InstallKind == selfupdate.InstallSystemd && i.opts.HelperEnabled()
}

// migratedPast reports whether this gateway migrated a database and was not
// built compatible with release, by its own record. The helper reads the
// same record and decides for itself.
func (i *Installer) migratedPast(release string) bool {
	root, err := os.OpenRoot(filepath.Join(i.opts.DataDir, SpoolName))
	if err != nil {
		return false
	}
	defer func() { _ = root.Close() }()
	var m Migrated
	if err := ReadJSON(root, MigratedFile, &m); err != nil || !SameRelease(m.Version, i.opts.Version) {
		return false
	}
	return len(m.Runs) > 0 && !SameRelease(m.CompatibleWith, release)
}

// Rollback asks the helper to put back the release the last upgrade
// replaced, which must be the one the caller names. It returns once the
// request is left; View reports what becomes of it.
func (i *Installer) Rollback(to, by string) error {
	now := i.opts.Now().UTC()
	i.mu.Lock()
	defer i.mu.Unlock()
	_, history := i.readState()
	have := i.rollback(history)
	switch {
	case !i.helped():
		return ErrBlocked
	case have.To == "" || !SameRelease(have.To, to):
		return ErrNoPrevious
	case have.NeedsRestore:
		return ErrNeedsRestore
	case i.busyLocked(now):
		return ErrBusy
	}
	req := Request{Version: have.To, RequestedBy: SanitizeRequestedBy(by), RequestedAt: now, Rollback: true}
	if err := i.leave(req); err != nil {
		return err
	}
	i.local = &Status{
		Phase: PhaseRequested, Reason: ReasonRequested, Target: i.opts.Version, Previous: have.To,
		RequestedBy: req.RequestedBy, StartedAt: now,
	}
	i.requestedAt = i.opts.Now()
	logger.L.LogInfo("rolling back to the previous gateon release", "running", i.opts.Version, "previous", have.To,
		"requested_by", req.RequestedBy)
	return nil
}

// leave writes a request the helper needs no release for.
func (i *Installer) leave(req Request) error {
	root, err := openSpoolDir(i.opts.DataDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return WriteJSON(root, RequestFile, req, fileMode)
}
