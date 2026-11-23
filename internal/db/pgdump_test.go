// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
)

// postgresAt opens the test server's database at an earlier release's
// schema, with the data directory the dump goes to. The test skips without
// a server: CI runs these with GATEON_TEST_POSTGRES_DSN set.
func postgresAt(t *testing.T, last int) (*sql.DB, Dialect, string) {
	t.Helper()
	dsn := os.Getenv("GATEON_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEON_TEST_POSTGRES_DSN is not set")
	}
	testutil.LockPostgres(t, dsn)
	dataDir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dataDir)
	database, dialect, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { forgetPostgresSource(database); _ = database.Close() })
	probe := &schemaProbe{t: t, db: database, dialect: dialect}
	probe.reset()
	// The server is shared with other packages' tests. Left part-way through
	// the chain, the next one to migrate it would be upgrading an existing
	// database, and would leave a dump in its own working directory.
	t.Cleanup(probe.reset)
	if last > 0 {
		if err := migrateUpTo(database, dialect, last); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { requirePostgresDump.Store(false) })
	return database, dialect, dataDir
}

func dumps(t *testing.T, dataDir string) []string {
	t.Helper()
	found, err := filepath.Glob(filepath.Join(dataDir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// withoutPgDump hides the client program, as on a host that never had it.
func withoutPgDump(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

// TestAnExistingPostgresDatabaseIsDumpedBeforeItIsMigrated: until this, a
// PostgreSQL database was migrated in place with nothing taken first, and an
// upgrade that went wrong across more than one release had no way back but
// the operator's own backups, if there were any.
func TestAnExistingPostgresDatabaseIsDumpedBeforeItIsMigrated(t *testing.T) {
	const from = 62
	database, dialect, dataDir := postgresAt(t, from)
	o := observe(t)
	RequirePostgresDump(true)
	if err := Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	if got := lastMigration(t, database); got <= from {
		t.Fatalf("the database is still at migration %d", got)
	}
	if len(o.begun) != 1 || len(o.ended) != 1 || len(o.abandoned) != 0 {
		t.Fatalf("begun %d, ended %d, abandoned %d", len(o.begun), len(o.ended), len(o.abandoned))
	}
	dump := o.ended[0].Backup
	if dump == "" || filepath.Dir(dump) != dataDir || !strings.HasSuffix(dump, PostgresDumpSuffix) {
		t.Fatalf("the observer was told the dump is %q", dump)
	}
	if o.begun[0].Backup != dump || o.backupAtBegin {
		t.Fatalf("Begin named %q (already there: %v); it is what tells the helper to wait for the dump", o.begun[0].Backup, o.backupAtBegin)
	}
	info, err := os.Stat(dump)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != dumpFileMode {
		t.Fatalf("the dump holds password hashes and is %v", info.Mode().Perm())
	}
	// The dump is of the schema before the migration, and pg_restore reads it.
	listing, err := exec.Command("pg_restore", "--list", dump).CombinedOutput()
	if err != nil {
		t.Fatalf("pg_restore cannot read the dump: %v\n%s", err, listing)
	}
	if !strings.Contains(string(listing), "TABLE DATA public migrations") {
		t.Fatalf("the dump does not hold the gateway's tables:\n%s", listing)
	}
	data, err := exec.Command("pg_restore", "--data-only", "--table=migrations", "--file=-", dump).Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "\n63\t") || !strings.Contains(string(data), "\n62\t") {
		t.Fatalf("the dump was not taken before the migrations ran:\n%s", data)
	}
	if left := dumps(t, dataDir); len(left) != 1 {
		t.Fatalf("the data directory holds %v", left)
	}
}

// TestAPostgresMigrationWaitedForByTheHelperDoesNotRunWithoutItsDump: the
// helper then puts the previous release back on a database nothing touched.
func TestAPostgresMigrationWaitedForByTheHelperDoesNotRunWithoutItsDump(t *testing.T) {
	const from = 62
	database, dialect, dataDir := postgresAt(t, from)
	o := observe(t)
	RequirePostgresDump(true)
	withoutPgDump(t)
	err := Migrate(database, dialect)
	if !errors.Is(err, errNoDump) {
		t.Fatalf("got %v, want a refusal for the missing dump", err)
	}
	for _, want := range []string{"pg_dump is not installed", EnvMigrationBackup + "=false"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	if got := lastMigration(t, database); got != from {
		t.Fatalf("migration %d ran without a dump to go back to", got)
	}
	if len(o.abandoned) != 1 || len(o.ended) != 0 {
		t.Fatalf("abandoned %d, ended %d: the helper would be told a database was migrated", len(o.abandoned), len(o.ended))
	}
	if left := dumps(t, dataDir); len(left) != 0 {
		t.Fatalf("a refused dump left %v", left)
	}
}

// TestAPostgresMigrationNobodyCanRollBackRunsWithoutADumpAndSaysSo: a
// package upgrade or a new container image has no helper behind it, and a
// gateway that refuses to start there is an outage with no way back.
func TestAPostgresMigrationNobodyCanRollBackRunsWithoutADumpAndSaysSo(t *testing.T) {
	const from = 62
	database, dialect, _ := postgresAt(t, from)
	o := observe(t)
	withoutPgDump(t)
	if err := Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	if got := lastMigration(t, database); got <= from {
		t.Fatalf("the database is still at migration %d", got)
	}
	if len(o.ended) != 1 || o.ended[0].Backup != "" {
		t.Fatalf("the observer was told of a dump that was never taken: %+v", o.ended)
	}
}

func TestThePostgresDumpFollowsTheSameSwitchAsTheSQLiteCopy(t *testing.T) {
	database, dialect, dataDir := postgresAt(t, 62)
	o := observe(t)
	RequirePostgresDump(true)
	withoutPgDump(t) // not needed, and so not missed
	t.Setenv(EnvMigrationBackup, "false")
	if err := Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	if len(o.ended) != 1 || o.ended[0].Backup != "" || len(dumps(t, dataDir)) != 0 {
		t.Fatalf("a dump was taken with the backup switched off: %+v", o.ended)
	}
}

func TestAFreshPostgresDatabaseIsNotDumped(t *testing.T) {
	database, dialect, dataDir := postgresAt(t, 0)
	o := observe(t)
	RequirePostgresDump(true)
	withoutPgDump(t)
	if err := Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	if len(o.begun) != 0 || len(dumps(t, dataDir)) != 0 {
		t.Fatal("a database with nothing in it was dumped or reported")
	}
}

// TestADumpThatFailsLeavesTheLastGoodOne: the slot is replaced only by a
// complete dump, so a failed attempt does not cost the copy that was there.
func TestADumpThatFailsLeavesTheLastGoodOne(t *testing.T) {
	database, _, _ := postgresAt(t, 62)
	path, schema, err := postgresDumpPath(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("the last good dump"), dumpFileMode); err != nil {
		t.Fatal(err)
	}
	rememberPostgresSource(database, "postgres://nobody:wrong@127.0.0.1:1/none?connect_timeout=2")
	if err := dumpPostgres(database, path, schema); !errors.Is(err, errNoDump) {
		t.Fatalf("got %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "the last good dump" {
		t.Fatalf("the last good dump now holds %q", got)
	}
	if _, err := os.Stat(path + ".partial"); err == nil {
		t.Fatal("the failed attempt was left behind")
	}
}

// TestThePasswordNeverReachesTheCommandLine: every account on the host can
// read another process's arguments, and none can read its environment.
func TestThePasswordNeverReachesTheCommandLine(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("GATEON_PASETO_SECRET", "not-for-pg-dump")
	env, err := postgresEnv("postgres://gate%40on:s3cr%2Ft@db.internal:6432/gateon_prod?sslmode=verify-full&sslrootcert=/etc/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(env, "\n")
	for _, want := range []string{
		"PATH=/usr/bin", "PGHOST=db.internal", "PGPORT=6432", "PGUSER=gate@on", "PGPASSWORD=s3cr/t",
		"PGDATABASE=gateon_prod", "PGSSLMODE=verify-full", "PGSSLROOTCERT=/etc/ca.pem",
	} {
		if !strings.Contains(got+"\n", want+"\n") {
			t.Errorf("the environment lacks %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "not-for-pg-dump") {
		t.Error("the gateway's own secrets were handed to pg_dump")
	}
	args := strings.Join(dumpArgs(`we"ird`), " ")
	if strings.Contains(args, "s3cr") || strings.Contains(args, "db.internal") {
		t.Fatalf("the connection is on the command line: %s", args)
	}
	if !strings.Contains(args, `--schema="we""ird"`) || !strings.Contains(args, "--no-password") {
		t.Fatalf("got %s", args)
	}
	if _, err := postgresEnv("host=db user=gateon"); err == nil {
		t.Error("a string that is not a URL was taken for one")
	}
}

func TestADatabaseNameCannotLeaveTheDataDirectory(t *testing.T) {
	for name, want := range map[string]string{
		"gateon_prod": "gateon_prod", "../../etc/cron.d/x": "______etc_cron_d_x", "a b\x00c": "a_b_c", "": "database", "数据": "__",
	} {
		if got := fileSafe(name); got != want {
			t.Errorf("fileSafe(%q) = %q, want %q", name, got, want)
		}
	}
}
