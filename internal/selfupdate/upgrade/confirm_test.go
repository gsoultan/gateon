// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package upgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"

	"github.com/gsoultan/gateon/internal/db"
)

// site is the two directories of an install, with the helper's status set.
func site(t *testing.T, st Status) Dirs {
	t.Helper()
	dirs := Dirs{Data: t.TempDir(), State: t.TempDir()}
	root, err := os.OpenRoot(dirs.State)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := WriteJSON(root, StatusFile, st, 0o644); err != nil {
		t.Fatal(err)
	}
	return dirs
}

func readSpool(t *testing.T, dirs Dirs, name string, v any) error {
	t.Helper()
	root, err := os.OpenRoot(filepath.Join(dirs.Data, SpoolName))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return ReadJSON(root, name, v)
}

func always() bool { return true }

func TestAGatewayTheHelperWaitsForAnswersWithItsNonce(t *testing.T) {
	dirs := site(t, Status{Phase: PhaseRestarting, Expect: "1.8.3", Nonce: "n-1", Previous: "1.8.2"})
	Confirm(context.Background(), "1.8.3", dirs, always)
	var ready Ready
	if err := readSpool(t, dirs, ReadyFile, &ready); err != nil || ready != (Ready{Version: "1.8.3", Nonce: "n-1"}) {
		t.Fatalf("got %+v (%v)", ready, err)
	}
}

func TestAGatewayNobodyWaitsForSaysNothing(t *testing.T) {
	cases := map[string]Status{
		"another version expected": {Phase: PhaseRestarting, Expect: "1.8.4", Nonce: "n"},
		"an install long finished": {Phase: PhaseSucceeded, Target: "1.8.3"},
		"no nonce":                 {Phase: PhaseRestarting, Expect: "1.8.3"},
	}
	for name, st := range cases {
		dirs := site(t, st)
		Confirm(context.Background(), "1.8.3", dirs, always)
		var ready Ready
		if err := readSpool(t, dirs, ReadyFile, &ready); err == nil {
			t.Errorf("%s: the gateway answered %+v", name, ready)
		}
	}
	// And a host with no helper at all.
	Confirm(context.Background(), "1.8.3", Dirs{Data: t.TempDir(), State: filepath.Join(t.TempDir(), "absent")}, always)
}

func TestTheAnswerWaitsUntilTheGatewayIsReady(t *testing.T) {
	dirs := site(t, Status{Phase: PhaseRestarting, Expect: "1.8.3", Nonce: "n-1"})
	synctest.Test(t, func(t *testing.T) {
		asked := 0
		ready := func() bool { asked++; return asked > 8 }
		Confirm(t.Context(), "1.8.3", dirs, ready)
		if asked != 9 {
			t.Fatalf("readiness was asked %d times", asked)
		}
	})
	var ready Ready
	if err := readSpool(t, dirs, ReadyFile, &ready); err != nil {
		t.Fatalf("no answer once ready: %v", err)
	}
}

func TestAGatewayThatNeverBecomesReadyNeverAnswers(t *testing.T) {
	dirs := site(t, Status{Phase: PhaseRestarting, Expect: "1.8.3", Nonce: "n-1"})
	synctest.Test(t, func(t *testing.T) {
		Confirm(t.Context(), "1.8.3", dirs, func() bool { return false })
	})
	var ready Ready
	if err := readSpool(t, dirs, ReadyFile, &ready); err == nil {
		t.Fatal("a gateway that was never ready told the helper it was")
	}
}

func TestTheRecorderWritesEachMigrationAsItStartsAndEnds(t *testing.T) {
	dirs := Dirs{Data: t.TempDir()}
	r := NewRecorder("1.8.3", dirs.Data)
	run := db.MigrationRun{Driver: db.DriverSQLite, Database: "/d/gateon.db", Backup: "/d/gateon.db.bak"}
	r.Begin(run)
	var rec Migrated
	if err := readSpool(t, dirs, MigratedFile, &rec); err != nil || rec.Version != "1.8.3" || len(rec.Runs) != 1 || rec.Runs[0].Done {
		t.Fatalf("after Begin: %+v (%v)", rec, err)
	}
	r.End(run)
	r.Begin(db.MigrationRun{Driver: db.DriverPostgres})
	if err := readSpool(t, dirs, MigratedFile, &rec); err != nil || len(rec.Runs) != 2 || !rec.Runs[0].Done || rec.Runs[1].Dialect != DialectPostgres {
		t.Fatalf("after End: %+v (%v)", rec, err)
	}
	if rec.Runs[0].Backup != run.Backup || rec.Runs[0].Dialect != DialectSQLite {
		t.Fatalf("the run was recorded as %+v", rec.Runs[0])
	}
}

func TestTheRecorderIsBounded(t *testing.T) {
	dirs := Dirs{Data: t.TempDir()}
	r := NewRecorder("1.8.3", dirs.Data)
	for i := range maxMigrationRuns + 4 {
		r.Begin(db.MigrationRun{Driver: db.DriverSQLite, Database: filepath.Join("/d", string(rune('a'+i)))})
	}
	var rec Migrated
	if err := readSpool(t, dirs, MigratedFile, &rec); err != nil || len(rec.Runs) != maxMigrationRuns {
		t.Fatalf("%d runs recorded (%v), want %d", len(rec.Runs), err, maxMigrationRuns)
	}
}

// migratedSite is a host where 1.8.3 migrated a SQLite database, kept a
// copy, and failed; st is what the helper says about it.
func migratedSite(t *testing.T, st Status) (dirs Dirs, database string) {
	t.Helper()
	dirs = site(t, st)
	database = filepath.Join(dirs.Data, "gateon.db")
	files := map[string]string{
		database:                      "schema of 1.8.3",
		database + "-wal":             "log of 1.8.3",
		database + "-shm":             "index of 1.8.3",
		database + ".pre-upgrade.bak": "schema of 1.8.2",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), fileMode); err != nil {
			t.Fatal(err)
		}
	}
	r := NewRecorder("1.8.3", dirs.Data)
	r.End(db.MigrationRun{Driver: db.DriverSQLite, Database: database, Backup: database + ".pre-upgrade.bak"})
	return dirs, database
}

func content(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "<absent>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

var rollingBack = Status{
	Phase: PhaseRollingBack, Target: "1.8.3", Previous: "1.8.2", Expect: "1.8.2", Nonce: "n-2", RestoreDatabase: true,
}

func TestARollbackPutsTheDatabaseCopyBack(t *testing.T) {
	dirs, database := migratedSite(t, rollingBack)
	if err := RestoreIfOrdered("1.8.2", dirs); err != nil {
		t.Fatal(err)
	}
	if got := content(t, database); got != "schema of 1.8.2" {
		t.Fatalf("the database holds %q", got)
	}
	if got := content(t, database+restoredSuffix); got != "schema of 1.8.3" {
		t.Fatalf("what the failed version wrote was not kept: %q", got)
	}
	for _, sidecar := range []string{"-wal", "-shm"} {
		if got := content(t, database+sidecar); got != "<absent>" {
			t.Fatalf("the failed version's %s was left to be replayed into the copy", sidecar)
		}
	}
	// Once only: a second start must not copy over what the gateway has
	// written since.
	if err := os.WriteFile(database, []byte("written since"), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := RestoreIfOrdered("1.8.2", dirs); err != nil {
		t.Fatal(err)
	}
	if got := content(t, database); got != "written since" {
		t.Fatalf("a second start restored again: %q", got)
	}
}

func TestNothingIsRestoredUnlessTheHelperOrdersItNow(t *testing.T) {
	finished := rollingBack
	finished.Phase, finished.Nonce, finished.Expect = PhaseRolledBack, "", ""
	notOrdered := rollingBack
	notOrdered.RestoreDatabase = false
	otherTarget := rollingBack
	otherTarget.Target = "1.8.4"
	// The newer gateway, started on the schema it just migrated: the same
	// order to restore would undo its own migration on every start.
	goingForward := rollingBack
	goingForward.Phase, goingForward.Expect = PhaseRestarting, "1.8.3"
	cases := map[string]struct {
		st      Status
		version string
	}{
		"an upgrade still going forward": {goingForward, "1.8.3"},
		"a rollback long finished":       {finished, "1.8.2"},
		"a rollback with no restore":     {notOrdered, "1.8.2"},
		"a gateway that is not the one":  {rollingBack, "1.8.1"},
		"a record of another upgrade":    {otherTarget, "1.8.2"},
	}
	for name, c := range cases {
		dirs, database := migratedSite(t, c.st)
		if err := RestoreIfOrdered(c.version, dirs); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if got := content(t, database); got != "schema of 1.8.3" {
			t.Errorf("%s: the database was replaced with %q", name, got)
		}
	}
}

func TestARestoreThatCannotFinishIsAnError(t *testing.T) {
	dirs, database := migratedSite(t, rollingBack)
	if err := os.Remove(database + ".pre-upgrade.bak"); err != nil {
		t.Fatal(err)
	}
	if err := RestoreIfOrdered("1.8.2", dirs); err == nil {
		t.Fatal("the gateway would start on the newer schema with no copy to put back")
	}
	if got := content(t, database); got != "schema of 1.8.3" {
		t.Fatalf("the database was moved away with nothing to replace it: %q", got)
	}
}
