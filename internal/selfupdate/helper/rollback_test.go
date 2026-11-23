// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/selfupdate"
	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// upgraded is a host whose upgrade to offered reported ready: the helper
// that runs next is the offered release's own.
func upgraded(t *testing.T) *host { return upgradedMigrating(t, "") }

// upgradedMigrating is upgraded, by a release that migrated runs and was
// built compatible with compatibleWith.
func upgradedMigrating(t *testing.T, compatibleWith string, runs ...upgrade.MigrationRun) *host {
	t.Helper()
	h := newHost(t)
	h.svc.onStart = func(int) {
		if len(runs) > 0 {
			h.json(h.spool(upgrade.MigratedFile), upgrade.Migrated{Version: offered, CompatibleWith: compatibleWith, Runs: runs})
		}
		h.answer()
	}
	if st := h.run(); st.Phase != upgrade.PhaseSucceeded {
		t.Fatalf("the upgrade this test starts from ended %s/%q", st.Phase, st.Reason)
	}
	h.cfg.Version = offered
	h.svc.onStart = func(int) { h.answer() }
	return h
}

func (h *host) rollback(opts RollbackOptions) upgrade.Status {
	h.t.Helper()
	st, err := Rollback(context.Background(), h.cfg, opts)
	if err != nil {
		h.t.Fatalf("Rollback: %v", err)
	}
	return st
}

// untouched asserts a rollback that changed nothing.
func (h *host) untouched(st upgrade.Status, reason upgrade.Reason, startsBefore int) {
	h.t.Helper()
	if st.Phase != upgrade.PhaseRefused || st.Reason != reason {
		h.t.Fatalf("got %s/%q, want refused/%q", st.Phase, st.Reason, reason)
	}
	if got := h.installedBinary(); got != "new" {
		h.t.Fatalf("a refused rollback left the %s binary installed", got)
	}
	if h.svc.starts != startsBefore {
		h.t.Fatalf("a refused rollback restarted the gateway")
	}
}

// TestAnUpgradeThatReportedReadyCanStillBeRolledBack: until this, the
// previous binary was put back only when the new one failed to start. A
// release that started and then misbehaved could be left only by a
// downgrade that downloads, at the moment the operator least wants to wait.
func TestAnUpgradeThatReportedReadyCanStillBeRolledBack(t *testing.T) {
	h := upgraded(t)
	st := h.rollback(RollbackOptions{RequestedBy: "ada"})
	if st.Phase != upgrade.PhaseRolledBack || st.Reason != upgrade.ReasonRequested {
		t.Fatalf("got %s/%q", st.Phase, st.Reason)
	}
	if st.Target != offered || st.Previous != installed || st.RequestedBy != "ada" {
		t.Fatalf("the outcome names %q rolled back to %q by %q", st.Target, st.Previous, st.RequestedBy)
	}
	if got := h.installedBinary(); got != "old" {
		t.Fatalf("the %s binary is installed", got)
	}
	if h.svc.starts != 2 {
		t.Fatalf("the gateway was started %d times, want once to upgrade and once to roll back", h.svc.starts)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.StateDir, replacedFile)); err == nil {
		t.Fatal("the binary kept for the way back was left behind")
	}
}

// TestARollbackTheGatewayAsksForIsRun: the dashboard's half leaves a request
// like an install's, and the helper is started by the same unit.
func TestARollbackTheGatewayAsksForIsRun(t *testing.T) {
	h := upgraded(t)
	h.json(h.spool(upgrade.RequestFile), upgrade.Request{Version: installed, RequestedBy: "ada", RequestedAt: h.clock, Rollback: true})
	st := h.run()
	if st.Phase != upgrade.PhaseRolledBack || st.Reason != upgrade.ReasonRequested || h.installedBinary() != "old" {
		t.Fatalf("got %s/%q with the %s binary", st.Phase, st.Reason, h.installedBinary())
	}
	if _, err := os.Stat(h.spool(upgrade.RequestFile)); err == nil {
		t.Fatal("the request was left to be run again")
	}
}

// TestARollbackRequestCannotNameItsOwnRelease: the request says which
// release the asker was shown and decides nothing. An older release that is
// not the one root kept is not installed because a file named it.
func TestARollbackRequestCannotNameItsOwnRelease(t *testing.T) {
	for _, named := range []string{"1.8.1", "1.0.0", offered, "", "../previous-gateon"} {
		t.Run(named, func(t *testing.T) {
			h := upgraded(t)
			h.json(h.spool(upgrade.RequestFile), upgrade.Request{Version: named, RequestedAt: h.clock, Rollback: true})
			st := h.run()
			if named == "" {
				// An empty name accepts what was kept: that is the root shell's form.
				if st.Phase != upgrade.PhaseRolledBack {
					t.Fatalf("got %s/%q", st.Phase, st.Reason)
				}
				return
			}
			h.untouched(st, upgrade.ReasonNoPrevious, 1)
		})
	}
}

// TestARequestFileCannotOrderADatabasePutBack: putting a copy back discards
// what was written since, and the gateway's account may not decide that.
func TestARequestFileCannotOrderADatabasePutBack(t *testing.T) {
	h := upgraded(t)
	h.write(h.spool(upgrade.RequestFile), []byte(`{"version":"`+installed+`","rollback":true,"restore_database":true,"requested_at":"2026-11-13T02:00:00Z"}`))
	if _, err := Run(context.Background(), h.cfg); err == nil {
		t.Fatal("a request carrying restore_database was run")
	}
	if got := h.installedBinary(); got != "new" || h.svc.starts != 1 {
		t.Fatalf("the %s binary is installed after %d starts", got, h.svc.starts)
	}
}

func TestThereIsNothingToRollBackTo(t *testing.T) {
	t.Run("before any upgrade", func(t *testing.T) {
		h := newHost(t)
		h.write(h.cfg.BinaryPath, h.newBin)
		h.untouched(h.rollback(RollbackOptions{}), upgrade.ReasonNoPrevious, 0)
	})
	t.Run("after a rollback", func(t *testing.T) {
		h := upgraded(t)
		h.rollback(RollbackOptions{})
		h.cfg.Version = installed
		st := h.rollback(RollbackOptions{})
		if st.Phase != upgrade.PhaseRefused || st.Reason != upgrade.ReasonNoPrevious || h.svc.starts != 2 {
			t.Fatalf("got %s/%q after %d starts", st.Phase, st.Reason, h.svc.starts)
		}
	})
	t.Run("after an upgrade that rolled itself back", func(t *testing.T) {
		h := newHost(t)
		if st := h.run(); st.Phase != upgrade.PhaseRolledBack {
			t.Fatalf("got %s", st.Phase)
		}
		st := h.rollback(RollbackOptions{})
		if st.Phase != upgrade.PhaseRefused || st.Reason != upgrade.ReasonNoPrevious {
			t.Fatalf("got %s/%q", st.Phase, st.Reason)
		}
	})
	t.Run("when another release was installed over the upgrade", func(t *testing.T) {
		h := upgraded(t)
		h.cfg.Version = "1.9.0" // a package, say
		h.untouched(h.rollback(RollbackOptions{}), upgrade.ReasonNoPrevious, 1)
	})
	t.Run("when the kept binary is gone", func(t *testing.T) {
		h := upgraded(t)
		if err := os.Remove(filepath.Join(h.cfg.StateDir, previousFile)); err != nil {
			t.Fatal(err)
		}
		h.untouched(h.rollback(RollbackOptions{}), upgrade.ReasonNoPrevious, 1)
	})
	t.Run("a refused install in between hides nothing", func(t *testing.T) {
		h := upgraded(t)
		h.request("1.8.3") // not newer than what is installed now
		h.refusedInstall()
		if st := h.rollback(RollbackOptions{}); st.Phase != upgrade.PhaseRolledBack {
			t.Fatalf("got %s/%q", st.Phase, st.Reason)
		}
	})
}

func (h *host) refusedInstall() {
	h.t.Helper()
	if st := h.run(); st.Phase != upgrade.PhaseRefused {
		h.t.Fatalf("got %s/%q, want a refused install", st.Phase, st.Reason)
	}
}

// TestAPreviousReleaseThatDoesNotComeUpIsNotLeftInstalled: asking for a
// rollback must never leave a host worse off than not asking.
func TestAPreviousReleaseThatDoesNotComeUpIsNotLeftInstalled(t *testing.T) {
	h := upgraded(t)
	var waited []upgrade.Status
	h.svc.onStart = func(starts int) {
		waited = append(waited, h.status())
		if starts == 3 {
			h.answer() // the release that was running, put back
		}
	}
	st := h.rollback(RollbackOptions{})
	if st.Phase != upgrade.PhaseFailed || st.Reason != upgrade.ReasonPreviousNotReady {
		t.Fatalf("got %s/%q", st.Phase, st.Reason)
	}
	if got := h.installedBinary(); got != "new" {
		t.Fatalf("the %s binary is installed", got)
	}
	if len(waited) != 2 || waited[0].Expect != installed || waited[1].Expect != offered {
		t.Fatalf("the helper waited for %+v", waited)
	}
	if waited[1].Phase != upgrade.PhaseRestarting {
		t.Fatalf("the release put back was started under %s, in which it would look for a database to restore", waited[1].Phase)
	}
	// And the previous binary is still kept: the operator can try again.
	h.svc.onStart = func(int) { h.answer() }
	if st := h.rollback(RollbackOptions{}); st.Phase != upgrade.PhaseRolledBack {
		t.Fatalf("a second attempt ended %s/%q", st.Phase, st.Reason)
	}
}

func (h *host) status() upgrade.Status {
	h.t.Helper()
	var st upgrade.Status
	data, err := os.ReadFile(filepath.Join(h.cfg.StateDir, upgrade.StatusFile))
	if err != nil {
		h.t.Fatal(err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		h.t.Fatal(err)
	}
	return st
}

var (
	sqliteWithCopy = upgrade.MigrationRun{Dialect: upgrade.DialectSQLite, Database: "/d/gateon.db", Backup: "/d/gateon.db.bak", Done: true}
	sqliteNoCopy   = upgrade.MigrationRun{Dialect: upgrade.DialectSQLite, Database: "/d/gateon.db", Done: true}
	postgresNoCopy = upgrade.MigrationRun{Dialect: upgrade.DialectPostgres, Done: true}
)

// TestARollbackKeepsTheDatabaseWhenThePreviousReleaseRunsOnIt: an upgrade one
// release forward only added to the schema (ADR 0102), so going back loses
// nothing written since. Restoring the copy here would throw away every
// route and login made after the upgrade, to undo a change nobody needs undone.
func TestARollbackKeepsTheDatabaseWhenThePreviousReleaseRunsOnIt(t *testing.T) {
	for name, run := range map[string]upgrade.MigrationRun{"sqlite": sqliteWithCopy, "postgres": postgresNoCopy} {
		t.Run(name, func(t *testing.T) {
			h := upgradedMigrating(t, installed, run)
			var ordered upgrade.Status
			h.svc.onStart = func(int) { ordered = h.status(); h.answer() }
			st := h.rollback(RollbackOptions{})
			if st.Phase != upgrade.PhaseRolledBack || h.installedBinary() != "old" {
				t.Fatalf("got %s/%q with the %s binary", st.Phase, st.Reason, h.installedBinary())
			}
			if ordered.RestoreDatabase || st.RestoreDatabase {
				t.Fatal("the previous gateway was told to put a database copy back")
			}
		})
	}
}

// TestARollbackAcrossReleasesIsRefusedUntilRootSaysRestore: the previous
// release was never started on this schema, and the only way back discards
// data. That is not decided by a request file, nor by default.
func TestARollbackAcrossReleasesIsRefusedUntilRootSaysRestore(t *testing.T) {
	for name, run := range map[string]upgrade.MigrationRun{"sqlite": sqliteWithCopy, "sqlite without a copy": sqliteNoCopy, "postgres": postgresNoCopy} {
		t.Run(name, func(t *testing.T) {
			h := upgradedMigrating(t, "1.8.1", run)
			h.untouched(h.rollback(RollbackOptions{}), upgrade.ReasonNeedsRestore, 1)
			h.json(h.spool(upgrade.RequestFile), upgrade.Request{Version: installed, RequestedAt: h.clock, Rollback: true})
			h.untouched(h.run(), upgrade.ReasonNeedsRestore, 1)
		})
	}
}

func TestRootMayOrderTheCopyPutBack(t *testing.T) {
	h := upgradedMigrating(t, "1.8.1", sqliteWithCopy)
	var ordered upgrade.Status
	h.svc.onStart = func(int) { ordered = h.status(); h.answer() }
	st := h.rollback(RollbackOptions{RestoreDatabase: true})
	if st.Phase != upgrade.PhaseRolledBack || !st.RestoreDatabase || h.installedBinary() != "old" {
		t.Fatalf("got %s/%q restore=%v with the %s binary", st.Phase, st.Reason, st.RestoreDatabase, h.installedBinary())
	}
	if ordered.Phase != upgrade.PhaseRollingBack || !ordered.RestoreDatabase || ordered.Expect != installed || ordered.Target != offered {
		t.Fatalf("the previous gateway was started under %+v", ordered)
	}
}

// TestACopyThatDoesNotExistIsNotPromised: asked to restore a database there
// is no copy of, the helper refuses rather than roll back without it.
func TestACopyThatDoesNotExistIsNotPromised(t *testing.T) {
	for name, run := range map[string]upgrade.MigrationRun{"sqlite without a copy": sqliteNoCopy, "postgres": postgresNoCopy} {
		t.Run(name, func(t *testing.T) {
			h := upgradedMigrating(t, installed, run)
			h.untouched(h.rollback(RollbackOptions{RestoreDatabase: true}), upgrade.ReasonNeedsRestore, 1)
		})
	}
}

// firstHelperStatus is upgrade.Status as release 1.3.8 declared it, the
// first with a helper. It is frozen here on purpose.
type firstHelperStatus struct {
	Phase           string    `json:"phase"`
	Target          string    `json:"target"`
	Previous        string    `json:"previous"`
	Expect          string    `json:"expect,omitempty"`
	Nonce           string    `json:"nonce,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	RestoreDatabase bool      `json:"restore_database,omitempty"`
	RequestedBy     string    `json:"requested_by,omitempty"`
	Automatic       bool      `json:"automatic,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at,omitzero"`
}

func strictly(t *testing.T, path string, into any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		t.Fatalf("%s is not readable by the release being rolled back to: %v\n%s", filepath.Base(path), err, data)
	}
}

// TestTheRollbackStatusIsReadableByTheFirstHelperRelease: in a rollback the
// helper is the newer release and the gateway reading its status the older
// one, which refuses a file holding a field it does not know. It would then
// never answer, and every rollback would end with the newer release put back.
func TestTheRollbackStatusIsReadableByTheFirstHelperRelease(t *testing.T) {
	h := upgradedMigrating(t, installed, postgresNoCopy)
	statusFile := filepath.Join(h.cfg.StateDir, upgrade.StatusFile)
	h.svc.onStart = func(int) {
		var waiting firstHelperStatus
		strictly(t, statusFile, &waiting)
		if waiting.Phase != string(upgrade.PhaseRollingBack) || waiting.Expect != installed || waiting.Nonce == "" {
			t.Fatalf("the previous gateway would not answer %+v", waiting)
		}
		h.answer()
	}
	if st := h.rollback(RollbackOptions{}); st.Phase != upgrade.PhaseRolledBack {
		t.Fatalf("got %s/%q", st.Phase, st.Reason)
	}
	var finished firstHelperStatus
	strictly(t, statusFile, &finished)
	var history []firstHelperStatus
	strictly(t, filepath.Join(h.cfg.StateDir, upgrade.HistoryFile), &history)
	if len(history) != 2 {
		t.Fatalf("the history holds %d entries", len(history))
	}
}

type systemdCheck struct{}

func (systemdCheck) Status() selfupdate.Status {
	return selfupdate.Status{InstallKind: selfupdate.InstallSystemd}
}

// TestWhatTheGatewayAsksTheHelperRollsBack runs both halves against each
// other: the gateway's own code leaves the request, the helper acts on it,
// and the gateway's own code answers for the previous release.
func TestWhatTheGatewayAsksTheHelperRollsBack(t *testing.T) {
	h := upgraded(t)
	gateway := upgrade.NewInstaller(upgrade.Options{
		Version: offered, DataDir: h.cfg.DataDir, StateDir: h.cfg.StateDir, Checker: systemdCheck{},
		HelperEnabled: func() bool { return true }, Now: func() time.Time { return h.clock },
		Config: func() *gateonv1.UpdateConfig { return nil },
	})
	if got := gateway.View().Rollback.To; got != installed {
		t.Fatalf("the gateway offers a rollback to %q", got)
	}
	if err := gateway.Rollback(installed, "ada"); err != nil {
		t.Fatalf("the gateway could not ask: %v", err)
	}
	dirs := upgrade.Dirs{Data: h.cfg.DataDir, State: h.cfg.StateDir}
	h.svc.onStart = func(int) {
		if err := upgrade.RestoreIfOrdered(installed, dirs); err != nil {
			t.Errorf("the previous gateway refused to start: %v", err)
		}
		upgrade.Confirm(context.Background(), installed, dirs, func() bool { return true })
	}
	st := h.run()
	if st.Phase != upgrade.PhaseRolledBack || st.Reason != upgrade.ReasonRequested || st.RequestedBy != "ada" {
		t.Fatalf("got %+v", st)
	}
	if got := h.installedBinary(); got != "old" {
		t.Fatalf("the %s binary is installed", got)
	}
	if h.slept != 0 {
		t.Fatalf("the helper waited %s for an answer that was already there", h.slept)
	}
	if got := gateway.View(); got.Rollback.To != "" || got.Current == nil || got.Current.Phase != upgrade.PhaseRolledBack {
		t.Fatalf("after the rollback the gateway shows %+v with a rollback to %q", got.Current, got.Rollback.To)
	}
}

// TestAGatewayThatRefusedToMigrateWithoutItsBackupIsSimplyRolledBack: the
// new gateway said a PostgreSQL migration had begun, could not take the dump
// and took the word back. Across several releases the helper leaves a
// migrated PostgreSQL database under the new binary; here nothing migrated,
// and leaving a gateway that will not start installed would be the outage.
func TestAGatewayThatRefusedToMigrateWithoutItsBackupIsSimplyRolledBack(t *testing.T) {
	h := newHost(t)
	var ordered upgrade.Status
	h.svc.onStart = func(starts int) {
		if starts == 1 {
			rec := upgrade.NewRecorder(offered, "1.8.0", h.cfg.DataDir)
			run := db.MigrationRun{Driver: db.DriverPostgres, Backup: "/d/postgres-gateon.pre-upgrade.dump"}
			rec.Begin(run)
			run.Backup = ""
			rec.Abandon(run)
			return // and it exits
		}
		ordered = h.status()
		h.answer()
	}
	st := h.run()
	if st.Phase != upgrade.PhaseRolledBack || st.Reason != upgrade.ReasonNotReady || h.installedBinary() != "old" {
		t.Fatalf("got %s/%q with the %s binary", st.Phase, st.Reason, h.installedBinary())
	}
	if ordered.RestoreDatabase || st.RestoreDatabase || st.DatabaseKept {
		t.Fatalf("restore=%v kept=%v for a database nothing touched", st.RestoreDatabase, st.DatabaseKept)
	}
}
