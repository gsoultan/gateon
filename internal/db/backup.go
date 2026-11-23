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
// a false value: the copy of a SQLite file and the dump of a PostgreSQL
// database alike. Either needs about as much free disk as the database is
// large.
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
	// Backup is the copy taken first: of the SQLite file, or pg_dump's dump
	// of a PostgreSQL database. Empty when none was.
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
	// Abandon is called when the backup could not be taken and so no
	// migration ran: the database is as it was before Begin.
	Abandon(run MigrationRun)
}

var migrationObserver atomic.Pointer[MigrationObserver]

// SetMigrationObserver names who is told about migrations of an existing
// database. It is set once, before the first store opens.
func SetMigrationObserver(o MigrationObserver) {
	migrationObserver.Store(&o)
}

// prepareUpgrade runs before the first pending migration of a database that
// has been migrated before: it tells the observer, and copies a SQLite
// database aside or dumps a PostgreSQL one. A fresh database has nothing to
// lose and gets neither.
func prepareUpgrade(db *sql.DB, dialect Dialect) (MigrationRun, error) {
	if dialect.Driver != DriverSQLite {
		return prepareServerUpgrade(db, dialect)
	}
	run := MigrationRun{Driver: dialect.Driver, Database: sqliteMainFile(db)}
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
		abandonUpgrade(run)
		return run, fmt.Errorf("copy %s to %s before migrating it: %w (free the space, or set %s=0 to migrate without a copy)",
			run.Database, run.Backup, err, EnvMigrationBackup)
	}
	logger.L.LogInfo("copied the database aside before migrating it", "database", run.Database, "backup", run.Backup)
	return run, nil
}

// prepareServerUpgrade is prepareUpgrade for PostgreSQL: the database is on
// a server, so the copy is a dump taken by the server's own client program.
//
// Nothing restores this dump by itself. A PostgreSQL database may be shared
// by several gateways, and replacing it beneath the others is not something
// one of them decides at startup; the dump is there for an operator with
// pg_restore (doc/self-upgrade.md).
func prepareServerUpgrade(db *sql.DB, dialect Dialect) (MigrationRun, error) {
	run := MigrationRun{Driver: dialect.Driver}
	observer := migrationObserver.Load()
	begin := func() {
		if observer != nil {
			(*observer).Begin(run)
		}
	}
	if !migrationBackupEnabled() {
		begin()
		return run, nil
	}
	path, schema, err := postgresDumpPath(db)
	if err == nil {
		run.Backup = path
		begin()
		err = dumpPostgres(db, path, schema)
	}
	if err == nil {
		logger.L.LogInfo("dumped the database before migrating it", "dump", path, "schema", schema)
		return run, nil
	}
	run.Backup = ""
	if requirePostgresDump.Load() {
		abandonUpgrade(run)
		return run, fmt.Errorf("%w; it is not migrated without one (install the PostgreSQL client tools of the server's version, or set %s=false to migrate without a dump)",
			err, EnvMigrationBackup)
	}
	logger.L.LogWarn("MIGRATING A POSTGRESQL DATABASE WITHOUT A DUMP: none could be taken, and nothing is waiting to put the previous version back if this one is refused. Install the PostgreSQL client tools of the server's version to have one next time",
		"error", err)
	begin()
	return run, nil
}

// abandonUpgrade takes back what Begin said. Left standing, the record would
// tell the upgrade helper that this gateway migrated a database, and the
// helper would then restore a copy that does not exist, or leave a release
// that cannot start installed over a database nothing touched.
func abandonUpgrade(run MigrationRun) {
	if o := migrationObserver.Load(); o != nil {
		(*o).Abandon(run)
	}
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
