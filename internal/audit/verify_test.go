// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/testutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// installed makes m the package's manager for the test, as Init would.
func installed(t *testing.T) *AuditManager {
	t.Helper()
	m := managerOn(t, filepath.Join(t.TempDir(), "audit.db"))
	prev := manager
	manager = m
	t.Cleanup(func() { manager = prev })
	return m
}

func logEntries(m *AuditManager, n int) {
	for i := range n {
		m.log(context.Background(), "admin", "update", "global_config", "change "+strconv.Itoa(i), "198.51.100.7")
	}
}

func verifyAll(t *testing.T, req VerifyRequest) []VerifyResult {
	t.Helper()
	var pages []VerifyResult
	for range 100 {
		res, err := VerifyRange(context.Background(), req)
		if err != nil {
			t.Fatalf("VerifyRange: %v", err)
		}
		pages = append(pages, res)
		if res.NextAfterID == "" {
			return pages
		}
		req.AfterID = res.NextAfterID
	}
	t.Fatal("the range never completed")
	return nil
}

// TestVerifyRangeReportsAnIntactChain: the verifier the review found had no
// caller now runs over the stored log.
func TestVerifyRangeReportsAnIntactChain(t *testing.T) {
	m := installed(t)
	logEntries(m, 10)
	res, err := VerifyRange(context.Background(), VerifyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Break != nil || res.Checked != 10 || !res.Complete || res.NextAfterID != "" {
		t.Fatalf("an untouched log: %+v", res)
	}
}

// TestVerifyRangeFindsAnEditedEntry and names it.
func TestVerifyRangeFindsAnEditedEntry(t *testing.T) {
	m := installed(t)
	logEntries(m, 10)
	stored := storedEntries(t, m)
	victim := stored[4]
	if _, err := m.db.Exec("UPDATE audit_logs SET details = 'nothing to see' WHERE id = ?", victim.ID); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyRange(context.Background(), VerifyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Break == nil || res.Break.ID != victim.ID || res.Checked != 4 || res.Complete {
		t.Fatalf("an edited entry: %+v (break %+v), want a break at %s after 4 intact", res, res.Break, victim.ID)
	}
}

// TestVerifyRangeFindsADeletedEntry: its successor no longer follows.
func TestVerifyRangeFindsADeletedEntry(t *testing.T) {
	m := installed(t)
	logEntries(m, 10)
	stored := storedEntries(t, m)
	if _, err := m.db.Exec("DELETE FROM audit_logs WHERE id = ?", stored[6].ID); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyRange(context.Background(), VerifyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Break == nil || res.Break.ID != stored[7].ID {
		t.Fatalf("a deleted entry: %+v, want a break at its successor %s", res.Break, stored[7].ID)
	}
}

// TestVerifyRangeIsBoundedAndContinues: each call checks at most Limit
// entries and hands back where to continue; a break on a later page is found
// there, and the pages together cover the log once.
func TestVerifyRangeIsBoundedAndContinues(t *testing.T) {
	m := installed(t)
	logEntries(m, 25)
	pages := verifyAll(t, VerifyRequest{Limit: 10})
	total := 0
	for _, p := range pages {
		if p.Checked > 10 || p.Break != nil {
			t.Fatalf("page %+v", p)
		}
		total += p.Checked
	}
	if len(pages) != 3 || total != 25 || !pages[2].Complete {
		t.Fatalf("%d pages checking %d entries, want 3 pages and 25", len(pages), total)
	}

	stored := storedEntries(t, m)
	if _, err := m.db.Exec("UPDATE audit_logs SET user_id = 'someone-else' WHERE id = ?", stored[17].ID); err != nil {
		t.Fatal(err)
	}
	pages = verifyAll(t, VerifyRequest{Limit: 10})
	last := pages[len(pages)-1]
	if len(pages) != 2 || last.Break == nil || last.Break.ID != stored[17].ID {
		t.Fatalf("a break on the second page: %d pages, last %+v", len(pages), last)
	}
}

// TestVerifyRangeCapsTheWindow: a limit above MaxVerifyLimit is MaxVerifyLimit,
// so no caller can ask for the whole log in one call.
func TestVerifyRangeCapsTheWindow(t *testing.T) {
	m := installed(t)
	tx, err := m.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	at, prev := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), ""
	for i := range MaxVerifyLimit + 1 {
		e := AuditEntry{ID: strconv.Itoa(i), UserID: "admin", Action: "a", Timestamp: at.Add(time.Duration(i) * time.Second), PreviousHash: prev}
		e.Signature = signEntry(e, testKey)
		prev = e.Signature
		if _, err := tx.Exec("INSERT INTO audit_logs ("+entryColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			e.ID, e.UserID, e.Action, e.Resource, e.Details, e.Timestamp, e.IPAddress, e.Signature, e.PreviousHash); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyRange(context.Background(), VerifyRequest{Limit: MaxVerifyLimit * 10})
	if err != nil || res.Break != nil || res.Checked != MaxVerifyLimit || res.NextAfterID == "" {
		t.Fatalf("an oversized limit: checked %d, next %q, break %v, err %v; want %d and a cursor",
			res.Checked, res.NextAfterID, res.Break, err, MaxVerifyLimit)
	}
}

// TestVerifyRangeFromATimeChainsToTheEntryBefore: a window starting part way
// through the log is checked against the entry stored before it, so neither a
// gap at its start nor a forged first entry passes.
func TestVerifyRangeFromATimeChainsToTheEntryBefore(t *testing.T) {
	m := installed(t)
	logEntries(m, 8)
	stored := storedEntries(t, m)
	res, err := VerifyRange(context.Background(), VerifyRequest{From: stored[5].Timestamp})
	if err != nil || res.Break != nil || res.Checked != 3 {
		t.Fatalf("from the sixth entry: %+v %v", res, err)
	}
	if _, err := m.db.Exec("DELETE FROM audit_logs WHERE id = ?", stored[4].ID); err != nil {
		t.Fatal(err)
	}
	res, err = VerifyRange(context.Background(), VerifyRequest{From: stored[5].Timestamp})
	if err != nil || res.Break == nil || res.Break.ID != stored[5].ID {
		t.Fatalf("with the entry before the window deleted: %+v %v, want a break at %s", res, err, stored[5].ID)
	}
}

// TestUnsignedEntriesEndTheChain: entries written while signing was off are
// reported, and the chain that resumes after them verifies on its own. The
// writer used to carry the last signed hash across unsigned entries, so the
// resumed chain pointed past them and no window could verify it.
func TestUnsignedEntriesEndTheChain(t *testing.T) {
	m := installed(t)
	logEntries(m, 3)
	m.config = &gateonv1.AuditConfig{Enabled: true}
	logEntries(m, 2)
	m.config = &gateonv1.AuditConfig{Enabled: true, SignEntries: true, SignatureKey: testKey}
	logEntries(m, 3)
	stored := storedEntries(t, m)

	res, err := VerifyRange(context.Background(), VerifyRequest{})
	if err != nil || res.Break == nil || res.Break.ID != stored[3].ID {
		t.Fatalf("over the unsigned entries: %+v %v, want a break at the first unsigned one", res, err)
	}
	res, err = VerifyRange(context.Background(), VerifyRequest{From: stored[5].Timestamp})
	if err != nil || res.Break != nil || res.Checked != 3 {
		t.Fatalf("from the first entry signed again: %+v (break %+v) %v, want 3 intact", res, res.Break, err)
	}
}

// TestEntriesInOneClockTickAreCheckedInChainOrder: the window is read in
// (timestamp, id) order, and two entries written in one tick are not in id
// order -- the chain decides.
func TestEntriesInOneClockTickAreCheckedInChainOrder(t *testing.T) {
	m := installed(t)
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	first := AuditEntry{ID: "zzzz-written-first", UserID: "admin", Action: "a", Timestamp: at}
	first.Signature = signEntry(first, testKey)
	second := AuditEntry{ID: "aaaa-written-second", UserID: "admin", Action: "b", Timestamp: at, PreviousHash: first.Signature}
	second.Signature = signEntry(second, testKey)
	for _, e := range []AuditEntry{first, second} {
		if _, err := m.db.Exec(m.dialect.Rebind("INSERT INTO audit_logs ("+entryColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"),
			e.ID, e.UserID, e.Action, e.Resource, e.Details, e.Timestamp, e.IPAddress, e.Signature, e.PreviousHash); err != nil {
			t.Fatal(err)
		}
	}
	res, err := VerifyRange(context.Background(), VerifyRequest{})
	if err != nil || res.Break != nil || res.Checked != 2 {
		t.Fatalf("two entries in one tick: %+v (break %+v) %v", res, res.Break, err)
	}
}

// TestVerifyRangeOnPostgres: Postgres's TIMESTAMP keeps the wall clock and
// drops the offset, so a window's bounds have to be compared in the zone the
// entries were written in there too.
func TestVerifyRangeOnPostgres(t *testing.T) {
	dsn := os.Getenv("GATEON_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEON_TEST_POSTGRES_DSN not set")
	}
	testutil.LockPostgres(t, dsn)
	database, dialect, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	m := &AuditManager{
		config:      &gateonv1.AuditConfig{Enabled: true, SignEntries: true, SignatureKey: testKey},
		db:          database,
		dialect:     dialect,
		Broadcaster: &Broadcaster{subscribers: make(map[chan AuditEntry]struct{})},
		stop:        make(chan struct{}),
	}
	m.loadLastHash()
	prev := manager
	manager = m
	t.Cleanup(func() { manager = prev })

	from := time.Now().Add(-time.Millisecond)
	logEntries(m, 4)
	res, err := VerifyRange(context.Background(), VerifyRequest{From: from.UTC()})
	if err != nil || res.Break != nil || res.Checked != 4 {
		t.Fatalf("four entries on Postgres, from a UTC bound: %+v (break %v) %v", res, res.Break, err)
	}
}

func TestVerifyRangeRefusals(t *testing.T) {
	m := installed(t)
	logEntries(m, 2)
	if _, err := VerifyRange(context.Background(), VerifyRequest{AfterID: "no-such-entry"}); !errors.Is(err, ErrUnknownCursor) {
		t.Errorf("an unknown cursor: %v", err)
	}
	m.config = &gateonv1.AuditConfig{Enabled: true}
	if _, err := VerifyRange(context.Background(), VerifyRequest{}); !errors.Is(err, ErrSigningOff) {
		t.Errorf("with signing off: %v", err)
	}
	manager = nil
	if _, err := VerifyRange(context.Background(), VerifyRequest{}); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("with no manager: %v", err)
	}
}
