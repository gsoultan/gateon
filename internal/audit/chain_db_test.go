// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The existing chain tests verify synthetic entries built in memory. That proves
// the signing arithmetic and nothing about the log gateon actually keeps: the
// entries these exercise are written through the real insert path, read back out
// of the database, and verified from there.
//
// That distinction is the whole compliance claim. A chain that verifies only
// while it is still in the process that wrote it is not tamper-evidence.

// managerOn builds a manager against an explicit database path, so a test can
// simulate a restart by opening a second one on the same file. The shared helper
// in store_test.go allocates a fresh temp dir per call and cannot express that.
func managerOn(t *testing.T, path string) *AuditManager {
	t.Helper()
	database, dialect, err := db.Open("sqlite:" + path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(database, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	m := &AuditManager{
		config: &gateonv1.AuditConfig{
			Enabled: true, SignEntries: true, SignatureKey: testKey,
		},
		db:          database,
		dialect:     dialect,
		Broadcaster: &Broadcaster{subscribers: make(map[chan AuditEntry]struct{})},
		stop:        make(chan struct{}),
	}
	m.prepareStatements()
	t.Cleanup(func() {
		m.stmtMu.Lock()
		if m.stmtInsert != nil {
			_ = m.stmtInsert.Close()
			m.stmtInsert = nil
		}
		m.stmtMu.Unlock()
	})
	return m
}

// storedEntries reads the log back the way an external verifier would: ordered
// by timestamp, with no access to the writer's in-memory state.
func storedEntries(t *testing.T, m *AuditManager) []AuditEntry {
	t.Helper()
	rows, err := m.db.Query(
		"SELECT id,user_id,action,resource,details,timestamp,ip_address,signature,previous_hash " +
			"FROM audit_logs ORDER BY timestamp ASC")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.Resource, &e.Details,
			&e.Timestamp, &e.IPAddress, &e.Signature, &e.PreviousHash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

func writeEntries(m *AuditManager, n int, action string) {
	for i := 0; i < n; i++ {
		m.log(context.Background(), "operator", action, "resource", "details", "203.0.113.5")
	}
}

// A log written through the real path must verify when read back out of storage.
func TestStoredChainVerifies(t *testing.T) {
	m := managerOn(t, filepath.Join(t.TempDir(), "audit.db"))
	writeEntries(m, 25, "login")

	entries := storedEntries(t, m)
	if len(entries) != 25 {
		t.Fatalf("read back %d entries, want 25", len(entries))
	}
	if err := VerifyChain(entries, testKey, ""); err != nil {
		t.Fatalf("a chain gateon wrote does not verify: %v", err)
	}
}

// TestChainSurvivesRestart is what loadLastHash exists for. If a restarting
// process does not pick the chain back up where it left off, every entry after
// the restart is unverifiable -- and an attacker who can restart the process
// could otherwise start a fresh chain over a truncated log.
func TestChainSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")

	first := managerOn(t, path)
	writeEntries(first, 3, "before-restart")
	headBefore := first.lastHash

	second := managerOn(t, path)
	second.loadLastHash()

	if second.lastHash != headBefore {
		t.Fatalf("loadLastHash restored %q, want the previous head %q", second.lastHash, headBefore)
	}

	writeEntries(second, 3, "after-restart")

	entries := storedEntries(t, second)
	if len(entries) != 6 {
		t.Fatalf("read back %d entries, want 6", len(entries))
	}
	if err := VerifyChain(entries, testKey, ""); err != nil {
		t.Fatalf("chain broke across a restart: %v", err)
	}
}

// A burst shares timestamps far more readily than ordinary traffic, and the log
// has no insertion-order column -- id is a UUID -- so timestamp is the only
// handle a verifier has for ordering. This pins that a fast burst still reads
// back in an order the chain accepts.
func TestBurstStaysVerifiable(t *testing.T) {
	m := managerOn(t, filepath.Join(t.TempDir(), "audit.db"))
	writeEntries(m, 200, "burst")

	entries := storedEntries(t, m)
	if len(entries) != 200 {
		t.Fatalf("read back %d entries, want 200", len(entries))
	}
	if err := VerifyChain(entries, testKey, ""); err != nil {
		t.Fatalf("a burst-written chain does not verify: %v", err)
	}
}

// TestEditedRowIsDetected is the claim the audit log exists to make. Changing a
// stored entry must be visible, or signing it bought nothing.
func TestEditedRowIsDetected(t *testing.T) {
	m := managerOn(t, filepath.Join(t.TempDir(), "audit.db"))
	writeEntries(m, 5, "delete-user")

	before := storedEntries(t, m)
	if err := VerifyChain(before, testKey, ""); err != nil {
		t.Fatalf("chain did not verify before tampering: %v", err)
	}

	// Rewrite history: make a destructive action look like a harmless one.
	target := before[2].ID
	if _, err := m.db.Exec(
		m.dialect.Rebind("UPDATE audit_logs SET action = ? WHERE id = ?"), "view-user", target); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	after := storedEntries(t, m)
	err := VerifyChain(after, testKey, "")
	if err == nil {
		t.Fatal("an edited entry verified; the log is not tamper-evident")
	}

	var ce *ChainError
	if !errors.As(err, &ce) {
		t.Fatalf("got %T (%v), want a *ChainError naming the break", err, err)
	}
	if ce.Index != 2 {
		t.Errorf("ChainError.Index = %d, want 2 (the edited entry)", ce.Index)
	}
}

// Deleting an entry is the cheaper attack: no signature has to be forged, the
// record simply stops existing. The chain has to notice the gap.
func TestDeletedRowIsDetected(t *testing.T) {
	m := managerOn(t, filepath.Join(t.TempDir(), "audit.db"))
	writeEntries(m, 5, "escalate-privilege")

	before := storedEntries(t, m)
	if _, err := m.db.Exec(
		m.dialect.Rebind("DELETE FROM audit_logs WHERE id = ?"), before[2].ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	after := storedEntries(t, m)
	if len(after) != 4 {
		t.Fatalf("read back %d entries after deleting one, want 4", len(after))
	}
	if err := VerifyChain(after, testKey, ""); err == nil {
		t.Fatal("a deleted entry went unnoticed; the log can be truncated in the middle")
	}
}

// Truncating the tail is what an attacker does after acting: remove the most
// recent entries and hope the remainder still checks out. It does -- a hash
// chain cannot detect its own tail being cut, which is a real property worth
// pinning so nobody assumes otherwise.
func TestTailTruncationIsNotDetectableByTheChainAlone(t *testing.T) {
	m := managerOn(t, filepath.Join(t.TempDir(), "audit.db"))
	writeEntries(m, 5, "exfiltrate")

	entries := storedEntries(t, m)
	truncated := entries[:3]

	if err := VerifyChain(truncated, testKey, ""); err != nil {
		t.Fatalf("truncated prefix should still verify on its own: %v", err)
	}
	// Documented consequence: detecting this needs an external anchor -- a
	// counter, or the head published somewhere the gateway cannot rewrite.
}

// A verifier holding the wrong key must not silently accept the log.
func TestWrongKeyDoesNotVerify(t *testing.T) {
	m := managerOn(t, filepath.Join(t.TempDir(), "audit.db"))
	writeEntries(m, 3, "login")

	entries := storedEntries(t, m)
	if err := VerifyChain(entries, "not-the-signing-key", ""); err == nil {
		t.Fatal("the chain verified under the wrong key")
	}
	if err := VerifyChain(entries, "", ""); err == nil {
		t.Fatal("the chain verified with no key at all")
	}
}
