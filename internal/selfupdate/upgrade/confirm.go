// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
)

// The pacing of Confirm.
const (
	confirmPoll = 250 * time.Millisecond
	// confirmFor is how long a started gateway keeps trying to become ready
	// for a helper. The helper has given up long before.
	confirmFor = 20 * time.Minute
)

// expected reads the helper's status and reports it when the helper is
// waiting for the gateway of version.
func expected(stateDir, version string) (Status, bool) {
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return Status{}, false
	}
	defer func() { _ = root.Close() }()
	var st Status
	if err := ReadJSON(root, StatusFile, &st); err != nil {
		return Status{}, false
	}
	waiting := st.Phase == PhaseRestarting || st.Phase == PhaseRollingBack
	return st, waiting && st.Expect == version && st.Nonce != ""
}

// Confirm tells the upgrade helper that this gateway came up, once ready
// says it has: the helper is holding the previous binary and will put it
// back unless it hears. It does nothing when no helper is waiting for this
// version, which is every start that is not an upgrade.
func Confirm(ctx context.Context, version string, dirs Dirs, ready func() bool) {
	st, waiting := expected(dirs.State, version)
	if !waiting {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, confirmFor)
	defer cancel()
	ticker := time.NewTicker(confirmPoll)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
	root, err := openSpoolDir(dirs.Data)
	if err == nil {
		defer func() { _ = root.Close() }()
		err = WriteJSON(root, ReadyFile, Ready{Version: version, Nonce: st.Nonce}, fileMode)
	}
	if err != nil {
		logger.L.LogError("could not tell the upgrade helper this gateway is ready; it will put the previous version back",
			"error", err)
		return
	}
	logger.L.LogInfo("told the upgrade helper this gateway is ready", "version", version, "replaces", st.Previous)
}

// Dirs is the two directories an install is spread over.
type Dirs struct {
	// Data is the gateway's data directory, which holds the spool.
	Data string
	// State is the helper's directory.
	State string
}

func openSpoolDir(dataDir string) (*os.Root, error) {
	dir := filepath.Join(dataDir, SpoolName)
	if err := os.MkdirAll(dir, spoolMode); err != nil {
		return nil, err
	}
	return os.OpenRoot(dir)
}

// Recorder writes down which databases this gateway migrated, for the
// helper to read if the gateway then fails to become ready. It is a
// db.MigrationObserver.
type Recorder struct {
	dataDir string
	now     func() time.Time

	mu  sync.Mutex
	rec Migrated
}

// NewRecorder records the migrations of the gateway of version.
func NewRecorder(version, dataDir string) *Recorder {
	return &Recorder{dataDir: dataDir, now: time.Now, rec: Migrated{Version: version}}
}

// Begin records a migration that has started.
func (r *Recorder) Begin(run db.MigrationRun) { r.record(run, false) }

// End records that it finished.
func (r *Recorder) End(run db.MigrationRun) { r.record(run, true) }

func (r *Recorder) record(run db.MigrationRun, done bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := MigrationRun{Dialect: run.Driver, Database: run.Database, Backup: run.Backup, Done: done, At: r.now().UTC()}
	found := false
	for i, have := range r.rec.Runs {
		if have.Dialect == entry.Dialect && have.Database == entry.Database {
			r.rec.Runs[i], found = entry, true
		}
	}
	if !found && len(r.rec.Runs) < maxMigrationRuns {
		r.rec.Runs = append(r.rec.Runs, entry)
	}
	root, err := openSpoolDir(r.dataDir)
	if err == nil {
		defer func() { _ = root.Close() }()
		err = WriteJSON(root, MigratedFile, r.rec, fileMode)
	}
	if err != nil {
		logger.L.LogWarn("could not record the migration for the upgrade helper; a failed upgrade would be rolled back as if nothing had migrated",
			"error", err)
	}
}

// restoredSuffix names the database a failed upgrade left, kept beside the
// copy that replaced it.
const restoredSuffix = ".failed-upgrade"

// RestoreIfOrdered puts back the SQLite copies taken before a newer gateway
// migrated them, when the helper is rolling that gateway back and waiting
// for this one. It runs before any store opens.
//
// Two files must agree before anything is replaced: the helper's status,
// which this gateway cannot write, must order a restore for this version
// right now, and the newer gateway's own record must name the databases and
// their copies. A status left over from a rollback long finished orders
// nothing, so a later downgrade by hand never loses data to this.
func RestoreIfOrdered(version string, dirs Dirs) error {
	st, waiting := expected(dirs.State, version)
	if !waiting || st.Phase != PhaseRollingBack || !st.RestoreDatabase {
		return nil
	}
	root, err := openSpoolDir(dirs.Data)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	var rec Migrated
	if err := ReadJSON(root, MigratedFile, &rec); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if rec.Version != st.Target {
		return nil
	}
	for _, run := range rec.Runs {
		if run.Dialect != DialectSQLite || run.Backup == "" || run.Database == "" {
			continue
		}
		if err := restoreSQLite(run.Database, run.Backup); err != nil {
			return fmt.Errorf("put %s back from %s: %w", run.Database, run.Backup, err)
		}
		logger.L.LogWarn("put the database back to the copy taken before the failed upgrade; what the newer version wrote is kept beside it",
			"database", run.Database, "kept", run.Database+restoredSuffix, "failed_version", st.Target)
	}
	return root.Remove(MigratedFile)
}

// restoreSQLite replaces database with backup. Each step can be repeated:
// a gateway killed part-way is restarted by systemd and runs this again.
func restoreSQLite(database, backup string) error {
	staged := database + ".restoring"
	if err := copyPrivate(backup, staged); err != nil {
		return err
	}
	if err := os.Rename(database, database+restoredSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The write-ahead log and its index belong to the database that was just
	// moved away. Left behind, SQLite would replay them into the copy.
	for _, sidecar := range []string{"-wal", "-shm"} {
		if err := os.Remove(database + sidecar); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Rename(staged, database)
}

func copyPrivate(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- the gateway's own database copy, named by its own record.
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	// #nosec G304 -- beside the gateway's own database.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}
