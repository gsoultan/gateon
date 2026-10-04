// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// logged writes n entries one at a time and returns their ids in the order
// they were written: the anchor after each write is the entry it stored.
func logged(t *testing.T, m *AuditManager, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for range n {
		logEntries(m, 1)
		m.mu.RLock()
		ids = append(ids, m.anchorID)
		m.mu.RUnlock()
	}
	return ids
}

func deleteEntries(t *testing.T, m *AuditManager, ids []string) {
	t.Helper()
	for _, id := range ids {
		if _, err := m.db.Exec(m.dialect.Rebind("DELETE FROM audit_logs WHERE id = ?"), id); err != nil {
			t.Fatal(err)
		}
	}
}

// TestVerifyRangeFindsTheNewestEntriesRemoved is TRUTH-NEW-11: deleting the
// newest entries leaves a chain that still verifies, and the dashboard said
// "The audit log verifies". The newest entry this gateway stored is the
// anchor; a log that no longer holds it was cut from the end.
func TestVerifyRangeFindsTheNewestEntriesRemoved(t *testing.T) {
	m := installed(t)
	ids := logged(t, m, 10)
	deleteEntries(t, m, ids[7:])

	res, err := VerifyRange(context.Background(), VerifyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Break != nil || !res.Complete || res.Checked != 7 {
		t.Fatalf("what is left of the chain: %+v (break %v); want 7 intact entries, complete", res, res.Break)
	}
	if !res.TailMissing || res.TailAnchor.IsZero() {
		t.Fatalf("three entries removed from the end: tail_missing=%v anchor=%v; want the removal reported",
			res.TailMissing, res.TailAnchor)
	}
}

// TestVerifyRangeChecksTheTailOfAnIntactLog: an untouched log is not reported,
// and the answer says how far the tail was checked.
func TestVerifyRangeChecksTheTailOfAnIntactLog(t *testing.T) {
	m := installed(t)
	logged(t, m, 5)
	res, err := VerifyRange(context.Background(), VerifyRequest{})
	if err != nil || res.Break != nil || res.TailMissing {
		t.Fatalf("an intact log: %+v (break %v) %v", res, res.Break, err)
	}
	m.mu.RLock()
	want := m.anchorAt
	m.mu.RUnlock()
	if !res.TailAnchor.Equal(want) || want.IsZero() {
		t.Errorf("tail anchor %v, want the newest entry's time %v", res.TailAnchor, want)
	}
}

// TestTheTailIsCheckedOnlyWhenTheRangeRunsToNow: a range that ends earlier has
// nothing to say about the end of the log.
func TestTheTailIsCheckedOnlyWhenTheRangeRunsToNow(t *testing.T) {
	m := installed(t)
	ids := logged(t, m, 4)
	deleteEntries(t, m, ids[3:])
	res, err := VerifyRange(context.Background(), VerifyRequest{To: time.Now().Add(-time.Hour)})
	if err != nil || res.TailMissing || !res.TailAnchor.IsZero() {
		t.Errorf("a range ending an hour ago: %+v %v; want no tail check", res, err)
	}
}

// TestTheTailAnchorSurvivesARestartOnlyAsTheLogIs pins the limit the
// dashboard states: after a restart the anchor is read from the log, so a cut
// made while the gateway was stopped -- or before it restarted -- is not seen.
func TestTheTailAnchorSurvivesARestartOnlyAsTheLogIs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	before := managerOn(t, path)
	ids := logged(t, before, 6)
	deleteEntries(t, before, ids[4:])

	restarted := managerOn(t, path)
	restarted.loadLastHash()
	prev := manager
	manager = restarted
	t.Cleanup(func() { manager = prev })
	res, err := VerifyRange(context.Background(), VerifyRequest{})
	if err != nil || res.Break != nil || res.TailMissing || res.Checked != 4 {
		t.Errorf("after a restart over a cut log: %+v (break %v) %v; want it to read as intact -- the stated limit",
			res, res.Break, err)
	}
}

// TestTheAnchorIsLoadedAtStart: a gateway that has written nothing since it
// started still anchors on the newest entry it found, so a cut made after the
// start is seen.
func TestTheAnchorIsLoadedAtStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	ids := logged(t, managerOn(t, path), 3)

	restarted := managerOn(t, path)
	restarted.loadLastHash()
	prev := manager
	manager = restarted
	t.Cleanup(func() { manager = prev })
	deleteEntries(t, restarted, ids[2:])
	res, err := VerifyRange(context.Background(), VerifyRequest{})
	if err != nil || !res.TailMissing {
		t.Errorf("the newest entry found at start, removed after it: %+v %v; want tail_missing", res, err)
	}
}

// TestTheAnchorOnlyMovesForward: concurrent writers sign in order but can
// finish storing out of order; the one that finishes last must not pull the
// anchor back to an older entry, which would leave the newest unchecked.
func TestTheAnchorOnlyMovesForward(t *testing.T) {
	m := &AuditManager{}
	now := time.Now()
	m.noteStored(AuditEntry{ID: "newer", Timestamp: now})
	m.noteStored(AuditEntry{ID: "older", Timestamp: now.Add(-time.Millisecond)})
	if m.anchorID != "newer" {
		t.Errorf("anchor = %q after an older entry finished storing last; want %q", m.anchorID, "newer")
	}
}

// TestRetentionIsNotReportedAsTampering: an anchor older than the retention
// period may have been deleted by retention, and is not looked for.
func TestRetentionIsNotReportedAsTampering(t *testing.T) {
	m := installed(t)
	logged(t, m, 2)
	m.mu.Lock()
	m.config.RetentionDays = 1
	m.anchorID, m.anchorAt = "retained-away", time.Now().AddDate(0, 0, -3)
	m.mu.Unlock()
	res, err := VerifyRange(context.Background(), VerifyRequest{})
	if err != nil || res.TailMissing {
		t.Errorf("an anchor past retention: %+v %v; want no report", res, err)
	}
}

// TestAnEntryThatFailedToStoreIsNotTheAnchor: the anchor moves only once the
// log holds the entry, or a failed write would read as a deleted one.
func TestAnEntryThatFailedToStoreIsNotTheAnchor(t *testing.T) {
	m := installed(t)
	logged(t, m, 3)
	if _, err := m.db.Exec("ALTER TABLE audit_logs RENAME TO audit_logs_away"); err != nil {
		t.Fatal(err)
	}
	m.prepareStatements()
	logEntries(m, 1) // fails: there is no table to write to
	if _, err := m.db.Exec("ALTER TABLE audit_logs_away RENAME TO audit_logs"); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyRange(context.Background(), VerifyRequest{})
	if err != nil || res.TailMissing {
		t.Errorf("after a write that failed: %+v %v; want the stored entries' tail, not the lost one", res, err)
	}
}
