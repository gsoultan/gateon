// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package helper

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
)

// install replaces the binary with the staged one, restarts the gateway and
// waits for it. A gateway that does not come up is answered by recover.
func (r *run) install(ctx context.Context, staged string) upgrade.Status {
	previous := filepath.Join(r.cfg.StateDir, previousFile)
	if err := copyFile(r.cfg.BinaryPath, previous, binaryMode); err != nil {
		_ = os.Remove(staged)
		return r.finish(upgrade.PhaseRefused, upgrade.ReasonInstall, fmt.Errorf("keep the installed binary: %w", err))
	}
	if err := r.cfg.Service.Stop(ctx); err != nil {
		r.cfg.Logf("stopping the gateway reported: %v", err)
	}
	r.expect(upgrade.PhaseRestarting, r.status.Target)
	if err := os.Rename(staged, r.cfg.BinaryPath); err != nil {
		_ = os.Remove(staged)
		r.start(ctx)
		return r.finish(upgrade.PhaseRefused, upgrade.ReasonInstall, err)
	}
	r.start(ctx)
	if r.waitReady(ctx) {
		return r.finish(upgrade.PhaseSucceeded, upgrade.ReasonNone, nil)
	}
	return r.recover(ctx)
}

func (r *run) start(ctx context.Context) {
	if err := r.cfg.Service.Start(ctx); err != nil {
		r.cfg.Logf("starting the gateway reported: %v", err)
	}
}

// expect records which gateway the helper is waiting for, under a fresh
// nonce, and clears what an earlier gateway said. It is called while the
// service is stopped: the only process that can then read the nonce and
// answer it is the binary about to be started.
func (r *run) expect(phase upgrade.Phase, version string) {
	_ = r.data.Remove(spool(upgrade.ReadyFile))
	if phase == upgrade.PhaseRestarting {
		_ = r.data.Remove(spool(upgrade.MigratedFile))
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	r.status.Phase, r.status.Expect, r.status.Nonce = phase, version, hex.EncodeToString(nonce)
	r.write()
}

// waitReady waits for the expected gateway to answer the nonce. It gives up
// at the timeout, sooner when the service manager keeps restarting the
// gateway, and later, up to maxMigrationWait, while the gateway says it is
// still backing up or migrating a database.
func (r *run) waitReady(ctx context.Context) bool {
	started := r.cfg.Now()
	deadline := started.Add(r.cfg.ReadyTimeout)
	for ctx.Err() == nil {
		if r.answered() {
			return true
		}
		now := r.cfg.Now()
		if r.migration().inProgress {
			deadline = minTime(now.Add(r.cfg.ReadyTimeout), started.Add(maxMigrationWait))
		}
		if !now.Before(deadline) {
			return false
		}
		if r.cfg.Service.Restarts(ctx) >= crashLoopRestarts {
			r.cfg.Logf("the gateway was restarted %d times; not waiting out the timeout", crashLoopRestarts)
			return false
		}
		r.cfg.Sleep(ctx, r.cfg.Poll)
	}
	return false
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// answered reports whether the expected gateway wrote the nonce back.
func (r *run) answered() bool {
	var ready upgrade.Ready
	if err := upgrade.ReadJSON(r.data, spool(upgrade.ReadyFile), &ready); err != nil {
		return false
	}
	return ready.Nonce == r.status.Nonce && ready.Version == r.status.Expect
}

// migrated is what the new gateway said it did to its databases.
type migrated struct {
	// ran: it changed a schema.
	ran bool
	// inProgress: a backup or a migration has started and not finished.
	inProgress bool
	// restorable: every database it changed is SQLite with a backup.
	restorable bool
}

// migration reads the new gateway's migration record. It is the gateway's
// own word about itself; see the package comment for why that is enough.
func (r *run) migration() migrated {
	var m upgrade.Migrated
	if err := upgrade.ReadJSON(r.data, spool(upgrade.MigratedFile), &m); err != nil || m.Version != r.status.Target {
		return migrated{}
	}
	out := migrated{ran: len(m.Runs) > 0, restorable: true}
	for _, run := range m.Runs {
		if !run.Done {
			out.inProgress = true
		}
		if run.Dialect != upgrade.DialectSQLite || run.Backup == "" {
			out.restorable = false
		}
	}
	return out
}

// recover answers a new binary that did not become ready. Putting the old
// binary back is right unless the new one changed a database the old one
// cannot be given back: then the old binary would start on a schema it does
// not know, and the helper leaves the new one in place and says so.
func (r *run) recover(ctx context.Context) upgrade.Status {
	mig := r.migration()
	if mig.ran && !mig.restorable {
		return r.finish(upgrade.PhaseFailed, upgrade.ReasonMigrated, nil)
	}
	if err := r.cfg.Service.Stop(ctx); err != nil {
		r.cfg.Logf("stopping the gateway reported: %v", err)
	}
	r.status.RestoreDatabase = mig.ran
	r.expect(upgrade.PhaseRollingBack, r.status.Previous)
	previous := filepath.Join(r.cfg.StateDir, previousFile)
	if err := copyFile(previous, r.cfg.BinaryPath, binaryMode); err != nil {
		r.start(ctx)
		return r.finish(upgrade.PhaseFailed, upgrade.ReasonInstall, fmt.Errorf("put the previous binary back: %w", err))
	}
	r.start(ctx)
	if !r.waitReady(ctx) {
		// Unanswered, so nothing confirms the copy was put back: the outcome
		// must not say it was.
		r.status.RestoreDatabase = false
		r.cfg.Logf("the previous gateway (%s) is back in place and has not reported ready", r.status.Previous)
	}
	return r.finish(upgrade.PhaseRolledBack, upgrade.ReasonNotReady, nil)
}
