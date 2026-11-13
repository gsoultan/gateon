// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
)

// EnvMigrationBackup turns the copy taken before a migration off when it is
// a false value. The copy needs as much free disk as the database is large.
const EnvMigrationBackup = "GATEON_MIGRATION_BACKUP"

// BackupSuffix names the copy of a SQLite database taken before a newer
// gateway migrates it. One slot: the next migration replaces it, so the
// copies of ten upgrades do not add up.
const BackupSuffix = ".pre-upgrade.bak"

// MigrationRun describes one database being migrated by a gateway newer
// than the one that last opened it.
type MigrationRun struct {
	Driver string
	// Database is the SQLite file; empty for PostgreSQL.
	Database string
	// Backup is the copy taken first; empty when none was.
	Backup string
}

// MigrationObserver is told when an existing database is migrated. The
// upgrade helper decides from it whether a failed upgrade can be undone
// (ADR 0087): a schema the previous binary does not know is one it must not
// be started on.
type MigrationObserver interface {
	// Begin is called before the backup, which is the slow part.
	Begin(run MigrationRun)
	// End is called when every pending migration has been applied.
	End(run MigrationRun)
}

var migrationObserver atomic.Pointer[MigrationObserver]

// SetMigrationObserver names who is told about migrations of an existing
// database. It is set once, before the first store opens.
func SetMigrationObserver(o MigrationObserver) {
	migrationObserver.Store(&o)
}

// prepareUpgrade runs before the first pending migration of a database that
// has been migrated before: it tells the observer, and copies a SQLite
// database aside. A fresh database has nothing to lose and gets neither.
func prepareUpgrade(db *sql.DB, dialect Dialect) (MigrationRun, error) {
	run := MigrationRun{Driver: dialect.Driver}
	if dialect.Driver == DriverSQLite {
		run.Database = sqliteMainFile(db)
	}
	if run.Database != "" && migrationBackupEnabled() {
		run.Backup = run.Database + BackupSuffix
	}
	if o := migrationObserver.Load(); o != nil {
		(*o).Begin(run)
	}
	if run.Backup == "" {
		return run, nil
	}
	if err := backupSQLite(db, run.Backup); err != nil {
		return run, fmt.Errorf("copy %s to %s before migrating it: %w (free the space, or set %s=0 to migrate without a copy)",
			run.Database, run.Backup, err, EnvMigrationBackup)
	}
	logger.L.LogInfo("copied the database aside before migrating it", "database", run.Database, "backup", run.Backup)
	return run, nil
}

func finishUpgrade(run MigrationRun) {
	if o := migrationObserver.Load(); o != nil {
		(*o).End(run)
	}
}

// migrationBackupEnabled is the profile's default unless EnvMigrationBackup
// says otherwise.
func migrationBackupEnabled() bool {
	def := config.CurrentTierDefaults().MigrationBackup
	v := strings.TrimSpace(os.Getenv(EnvMigrationBackup))
	if v == "" {
		return def
	}
	on, err := strconv.ParseBool(v)
	if err != nil {
		logger.L.LogWarn("ignoring an unparseable value; using the profile default",
			"env", EnvMigrationBackup, "value", v, "default", def)
		return def
	}
	return on
}

// sqliteMainFile is the file behind a SQLite connection, or empty for a
// database held in memory.
func sqliteMainFile(db *sql.DB) string {
	rows, err := db.Query("PRAGMA database_list")
	if err != nil {
		return ""
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			seq        int
			name, file string
		)
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return ""
		}
		if name == "main" {
			return file
		}
	}
	return ""
}

// backupSQLite writes a consistent copy of the database to dst. VACUUM INTO
// reads through the connection, so the write-ahead log is included; it
// refuses an existing file, hence the remove.
func backupSQLite(db *sql.DB, dst string) error {
	if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := db.Exec("VACUUM INTO ?", dst); err != nil {
		_ = os.Remove(dst)
		return err
	}
	// The copy holds what the database holds: password hashes, tokens.
	return os.Chmod(dst, 0o600)
}
