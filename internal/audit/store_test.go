// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The chain is only worth anything if it survives the database. signEntry hashes
// Timestamp.Unix(), so how the driver stores and returns a time.Time is load
// bearing: a round-trip that shifted the timestamp by a second, or dropped the
// zone in a way that changed the instant, would invalidate every signature and
// nobody would find out until someone tried to verify — which, before
// VerifyChain existed, nobody could.
//
// Init cannot be used here: it is guarded by sync.Once and installs a package
// global, so a test suite gets exactly one. Building the manager directly is
// what makes these tests independent of each other and of ordering.
func newTestManager(t *testing.T, cfg *gateonv1.AuditConfig) *AuditManager {
	t.Helper()
	dsn := "sqlite:" + filepath.Join(t.TempDir(), "audit_test.db")

	database, dialect, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	if err := db.Migrate(database, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	m := &AuditManager{
		config:      cfg,
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

func signingConfig(key string) *gateonv1.AuditConfig {
	return &gateonv1.AuditConfig{Enabled: true, SignEntries: true, SignatureKey: key}
}

// readChain pulls every entry back out oldest-first, which is the order
// VerifyChain requires and the opposite of what GetLogs returns.
func readChain(t *testing.T, m *AuditManager) []AuditEntry {
	t.Helper()
	query := m.dialect.Rebind(
		"SELECT id, user_id, action, resource, details, timestamp, ip_address, signature, previous_hash " +
			"FROM audit_logs ORDER BY timestamp ASC, id ASC")
	rows, err := m.db.Query(query)
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

// The end-to-end claim: entries written through log() and read back out of SQL
// form a chain that verifies.
func TestLog_ChainSurvivesTheDatabaseRoundTrip(t *testing.T) {
	m := newTestManager(t, signingConfig(testKey))
	ctx := context.Background()

	for _, a := range []string{"login", "update_route", "delete_user", "export_config"} {
		m.log(ctx, "admin", a, "system", "detail for "+a, "203.0.113.7")
	}

	entries := readChain(t, m)
	if len(entries) != 4 {
		t.Fatalf("got %d entries, want 4", len(entries))
	}
	if err := VerifyChain(entries, testKey, ""); err != nil {
		t.Fatalf("a chain written by log() must verify after a round trip: %v", err)
	}
}

// And the round-tripped chain must still be tamper-evident: edit a row the way
// someone with database access would, and verification must fail.
func TestLog_TamperingWithAPersistedRowIsDetected(t *testing.T) {
	m := newTestManager(t, signingConfig(testKey))
	ctx := context.Background()

	m.log(ctx, "admin", "login", "system", "ok", "203.0.113.7")
	m.log(ctx, "admin", "delete_user", "users", "removed mallory", "203.0.113.7")
	m.log(ctx, "admin", "logout", "system", "ok", "203.0.113.7")

	before := readChain(t, m)
	if err := VerifyChain(before, testKey, ""); err != nil {
		t.Fatalf("sanity: chain should verify before tampering: %v", err)
	}

	// Rewrite history directly in the store, leaving the signature in place.
	upd := m.dialect.Rebind("UPDATE audit_logs SET details = ? WHERE action = ?")
	if _, err := m.db.Exec(upd, "routine cleanup", "delete_user"); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	err := VerifyChain(readChain(t, m), testKey, "")
	if err == nil {
		t.Fatal("editing a persisted row must break verification")
	}
	ce := chainErr(t, err)
	if ce.Index != 1 {
		t.Fatalf("Index = %d, want 1 (the edited row)", ce.Index)
	}
}

// Deleting the record of an action is the attack the chain exists to catch.
func TestLog_DeletingAPersistedRowIsDetected(t *testing.T) {
	m := newTestManager(t, signingConfig(testKey))
	ctx := context.Background()

	for _, a := range []string{"login", "escalate_privilege", "logout"} {
		m.log(ctx, "mallory", a, "system", a, "198.51.100.9")
	}

	del := m.dialect.Rebind("DELETE FROM audit_logs WHERE action = ?")
	if _, err := m.db.Exec(del, "escalate_privilege"); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	if err := VerifyChain(readChain(t, m), testKey, ""); err == nil {
		t.Fatal("deleting a persisted row must break verification")
	}
}

// Each entry must chain to the one before it, not all to the same predecessor.
// log() holds the manager lock across read-lastHash → sign → update precisely so
// concurrent writers cannot fork the chain onto a shared previous_hash.
func TestLog_EntriesChainToTheirPredecessor(t *testing.T) {
	m := newTestManager(t, signingConfig(testKey))
	ctx := context.Background()

	for i := range 5 {
		m.log(ctx, "admin", "action", "system", string(rune('a'+i)), "203.0.113.7")
	}

	entries := readChain(t, m)
	if entries[0].PreviousHash != "" {
		t.Fatalf("first entry PreviousHash = %q, want empty", entries[0].PreviousHash)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].PreviousHash != entries[i-1].Signature {
			t.Fatalf("entry %d chains to %q, want its predecessor's %q",
				i, entries[i].PreviousHash, entries[i-1].Signature)
		}
	}
}

// Concurrent writers must produce one linear chain, never a fork. Run with
// -race for the lock itself to be checked.
func TestLog_ConcurrentWritersProduceOneLinearChain(t *testing.T) {
	m := newTestManager(t, signingConfig(testKey))
	ctx := context.Background()

	const writers, each = 8, 12
	done := make(chan struct{})
	for w := range writers {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := range each {
				m.log(ctx, "admin", "concurrent", "system",
					string(rune('a'+w))+string(rune('0'+i)), "203.0.113.7")
			}
		}(w)
	}
	for range writers {
		<-done
	}

	entries := readChain(t, m)
	if len(entries) != writers*each {
		t.Fatalf("got %d entries, want %d", len(entries), writers*each)
	}

	// A fork shows up as two entries claiming the same predecessor.
	seen := make(map[string]string, len(entries))
	for _, e := range entries {
		if prior, dup := seen[e.PreviousHash]; dup {
			t.Fatalf("chain forked: entries %s and %s both chain to %q", prior, e.ID, e.PreviousHash)
		}
		seen[e.PreviousHash] = e.ID
	}

	// Every signature must be distinct — a repeat would mean two identical
	// entries at the same point in the chain.
	sigs := make([]string, 0, len(entries))
	for _, e := range entries {
		sigs = append(sigs, e.Signature)
	}
	slices.Sort(sigs)
	if uniq := slices.Compact(sigs); len(uniq) != len(entries) {
		t.Fatalf("got %d distinct signatures across %d entries; two entries signed identically",
			len(uniq), len(entries))
	}
}

// Signing off means no signature is written. The entries are then not
// tamper-evident, and VerifyChain must say so rather than pass them.
func TestLog_UnsignedWhenSigningDisabled(t *testing.T) {
	m := newTestManager(t, &gateonv1.AuditConfig{Enabled: true, SignEntries: false})
	ctx := context.Background()

	m.log(ctx, "admin", "login", "system", "ok", "203.0.113.7")

	entries := readChain(t, m)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Signature != "" {
		t.Fatalf("Signature = %q, want empty with signing disabled", entries[0].Signature)
	}
	if err := VerifyChain(entries, testKey, ""); err == nil {
		t.Fatal("unsigned entries must not pass verification")
	}
}

// Disabling audit entirely writes nothing.
func TestLog_DisabledWritesNothing(t *testing.T) {
	m := newTestManager(t, &gateonv1.AuditConfig{Enabled: false, SignEntries: true, SignatureKey: testKey})

	m.log(context.Background(), "admin", "login", "system", "ok", "203.0.113.7")

	if entries := readChain(t, m); len(entries) != 0 {
		t.Fatalf("got %d entries, want none while audit is disabled", len(entries))
	}
}
