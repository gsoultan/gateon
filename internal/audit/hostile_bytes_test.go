// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/db"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestEntryCarryingBytesPostgresRefusesIsStillWritten.
//
// Every security threat is also written to the audit log, and its details and
// resource are copied from the request that caused it. Postgres refuses a TEXT
// value that is not valid UTF-8 or that contains NUL, so on Postgres the entry
// for a request carrying such a byte failed to insert and was only logged as a
// write error: the tamper-evident record skipped exactly the requests an
// attacker chose to shape. The entry must be written, and must still verify
// against its own signature.
func TestEntryCarryingBytesPostgresRefusesIsStillWritten(t *testing.T) {
	dsn := os.Getenv("GATEON_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEON_TEST_POSTGRES_DSN not set; SQLite stores these bytes and never refused them")
	}
	database, dialect, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(database, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	m := &AuditManager{
		config:      &gateonv1.AuditConfig{Enabled: true, SignEntries: true, SignatureKey: testKey},
		db:          database,
		dialect:     dialect,
		Broadcaster: &Broadcaster{subscribers: make(map[chan AuditEntry]struct{})},
		stop:        make(chan struct{}),
	}
	m.prepareStatements()
	t.Cleanup(func() { _ = m.stmtInsert.Close() })

	marker := fmt.Sprintf("hostile-bytes-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = database.Exec(dialect.Rebind("DELETE FROM audit_logs WHERE user_id = ?"), marker)
	})

	m.log(context.Background(), marker, "waf_block", "/a\x00b",
		"Severity: high, Details: sqlmap/1.8\xff in User-Agent, Action: blocked", "203.0.113.92")

	stored := storedEntriesFor(t, m, marker)
	if len(stored) != 1 {
		t.Fatalf("got %d audit entries for a request carrying NUL and \\xff, want 1", len(stored))
	}
	if err := VerifyChain(stored, testKey, stored[0].PreviousHash); err != nil {
		t.Errorf("the entry was written but does not verify against its own signature: %v", err)
	}
}

func storedEntriesFor(t *testing.T, m *AuditManager, userID string) []AuditEntry {
	t.Helper()
	rows, err := m.db.Query(m.dialect.Rebind(
		"SELECT id,user_id,action,resource,details,timestamp,ip_address,signature,previous_hash "+
			"FROM audit_logs WHERE user_id = ? ORDER BY timestamp ASC"), userID)
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
