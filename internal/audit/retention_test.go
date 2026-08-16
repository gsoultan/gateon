// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Retention deletes audit rows on a timer. An audit log that silently drops
// entries fails a compliance review exactly as hard as one that can be edited,
// so this path deserves the same scrutiny as the signing chain — and it had no
// tests at all.

// insertAt writes an entry with a chosen timestamp, so retention can be
// exercised without waiting or sleeping.
func insertAt(t *testing.T, m *AuditManager, id string, ts time.Time) {
	t.Helper()
	query := m.dialect.Rebind(
		"INSERT INTO audit_logs (id, user_id, action, resource, details, timestamp, ip_address, signature, previous_hash) " +
			"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if _, err := m.db.Exec(query, id, "admin", "action", "system", "detail", ts, "203.0.113.7", "sig-"+id, ""); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

func countRows(t *testing.T, m *AuditManager) int {
	t.Helper()
	var n int
	if err := m.db.QueryRow("SELECT COUNT(*) FROM audit_logs").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// A global config saved without an audit block leaves conf.Audit nil, and
// UpdateConfig assigns it through. checkRetention then reads m.config.RetentionDays
// as a struct field rather than through the nil-safe generated getter, so it
// panics — inside runRetentionTask's goroutine, which has no recover, so it
// takes the process down. log() guards for nil config; this path did not.
// Deliberately no recover(): a panic here should crash the test binary with the
// nil dereference in the trace, which is a loud, immediate failure that names
// the line. Catching it and calling t.Fatalf reads as tidier but is worse — the
// panic leaves m.mu read-locked (checkRetention takes RLock on the line before
// the fault and has no defer), so the recovered version deadlocks the runner
// instead of failing it.
func TestCheckRetention_NilConfigDoesNotPanic(t *testing.T) {
	m := newTestManager(t, nil)
	m.checkRetention()
}

func TestCheckRetention_ZeroRetentionKeepsEverything(t *testing.T) {
	m := newTestManager(t, &gateonv1.AuditConfig{Enabled: true, RetentionDays: 0})
	insertAt(t, m, "old", time.Now().AddDate(0, 0, -400))

	m.checkRetention()

	if n := countRows(t, m); n != 1 {
		t.Fatalf("got %d rows, want 1: retention 0 means keep forever", n)
	}
}

func TestCheckRetention_DeletesOnlyBeyondTheCutoff(t *testing.T) {
	m := newTestManager(t, &gateonv1.AuditConfig{Enabled: true, RetentionDays: 30})
	insertAt(t, m, "ancient", time.Now().AddDate(0, 0, -90))
	insertAt(t, m, "stale", time.Now().AddDate(0, 0, -31))
	insertAt(t, m, "fresh", time.Now().AddDate(0, 0, -1))

	m.checkRetention()

	if n := countRows(t, m); n != 1 {
		t.Fatalf("got %d rows, want 1 (only the fresh entry)", n)
	}
	var id string
	if err := m.db.QueryRow("SELECT id FROM audit_logs").Scan(&id); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if id != "fresh" {
		t.Fatalf("survivor is %q, want \"fresh\"", id)
	}
}

// The contract that matters most: if archiving fails, nothing may be deleted.
// Otherwise a failed backup becomes permanent data loss.
func TestCheckRetention_KeepsRowsWhenArchivingFails(t *testing.T) {
	m := newTestManager(t, &gateonv1.AuditConfig{
		Enabled: true, RetentionDays: 30, ArchiveOnRetention: true,
	})
	insertAt(t, m, "old", time.Now().AddDate(0, 0, -90))

	// Point the data dir at a regular file, so creating <dir>/audit/archives
	// fails with ENOTDIR and archiveLogs must report it.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Setenv("GATEON_DATA_DIR", blocker)

	m.checkRetention()

	if n := countRows(t, m); n != 1 {
		t.Fatalf("got %d rows, want the row kept: archiving failed, so deletion must not proceed", n)
	}
}

func TestCheckRetention_ArchivesThenDeletes(t *testing.T) {
	m := newTestManager(t, &gateonv1.AuditConfig{
		Enabled: true, RetentionDays: 30, ArchiveOnRetention: true,
	})
	insertAt(t, m, "old-1", time.Now().AddDate(0, 0, -90))
	insertAt(t, m, "old-2", time.Now().AddDate(0, 0, -60))

	dataDir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dataDir)

	m.checkRetention()

	if n := countRows(t, m); n != 0 {
		t.Fatalf("got %d rows, want 0 after a successful archive", n)
	}

	archives, err := filepath.Glob(filepath.Join(dataDir, "audit", "archives", "*.json.br"))
	if err != nil || len(archives) != 1 {
		t.Fatalf("archives = %v (err %v), want exactly one", archives, err)
	}

	// The archive must be readable and complete — this is what the deleted rows
	// were traded for.
	raw, err := os.ReadFile(archives[0])
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	var restored []AuditEntry
	if err := json.NewDecoder(brotli.NewReader(bytes.NewReader(raw))).Decode(&restored); err != nil {
		t.Fatalf("archive is not valid brotli-compressed JSON: %v", err)
	}
	if len(restored) != 2 {
		t.Fatalf("archive holds %d entries, want 2", len(restored))
	}
}

// failingWriter fails partway through, which is what a full disk looks like to
// the encoder.
type failingWriter struct {
	budget int
}

var errWriteFailed = errors.New("simulated write failure")

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.budget <= 0 {
		return 0, errWriteFailed
	}
	if len(p) > w.budget {
		n := w.budget
		w.budget = 0
		return n, errWriteFailed
	}
	w.budget -= len(p)
	return len(p), nil
}

// The brotli writer buffers, and its final block is emitted by Close. When Close
// was deferred, that flush ran after the function had already returned nil — so
// a write failure at flush time was invisible and checkRetention went on to
// delete the rows the archive was supposed to preserve.
func TestWriteArchive_ReportsFlushFailure(t *testing.T) {
	logs := []AuditEntry{{ID: "a", UserID: "admin", Action: "x", Timestamp: time.Now()}}

	if err := writeArchive(&failingWriter{budget: 0}, logs); err == nil {
		t.Fatal("writeArchive must report a write failure, not swallow it")
	}
}

func TestWriteArchive_RoundTripsEntries(t *testing.T) {
	logs := buildChain(t, 4, testKey)

	var buf bytes.Buffer
	if err := writeArchive(&buf, logs); err != nil {
		t.Fatalf("writeArchive: %v", err)
	}

	var restored []AuditEntry
	if err := json.NewDecoder(brotli.NewReader(&buf)).Decode(&restored); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(restored) != len(logs) {
		t.Fatalf("got %d entries, want %d", len(restored), len(logs))
	}
	// An archive whose chain no longer verifies is not an audit record.
	if err := VerifyChain(restored, testKey, ""); err != nil {
		t.Fatalf("archived chain must still verify: %v", err)
	}
}

// A truncated archive left on disk looks like a valid backup. If the write
// failed, the file must not survive to be trusted later.
func TestArchiveLogs_LeavesNoFileWhenTheWriteFails(t *testing.T) {
	m := newTestManager(t, &gateonv1.AuditConfig{
		Enabled: true, RetentionDays: 1, ArchiveOnRetention: true,
	})
	insertAt(t, m, "old", time.Now().AddDate(0, 0, -30))

	dataDir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dataDir)

	// Make the archive directory read-only so os.Create fails after MkdirAll.
	archiveDir := filepath.Join(dataDir, "audit", "archives")
	if err := os.MkdirAll(archiveDir, 0o750); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.Chmod(archiveDir, 0o500); err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(archiveDir, 0o750) })

	if err := m.archiveLogs(time.Now()); err == nil {
		t.Fatal("archiveLogs must fail when it cannot create the file")
	}

	files, _ := filepath.Glob(filepath.Join(archiveDir, "*"))
	if len(files) != 0 {
		t.Fatalf("left %v behind; a partial archive must not survive", files)
	}
	// And the rows must still be there.
	if n := countRows(t, m); n != 1 {
		t.Fatalf("got %d rows, want the row preserved", n)
	}
}
