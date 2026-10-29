// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"testing"
	"time"
)

// The hourly telemetry prune used to DELETE audit_logs rows past
// log.audit_log_retention_days on its own, without archiving them, while the
// audit manager archived on its separate audit.retention_days schedule. With
// the UI's default of 90 against an audit retention of 365, entries 90 to 365
// days old were destroyed before any archive saw them. The audit manager now
// owns every audit delete; the telemetry prune must leave the table alone.
func TestPruneLeavesAuditLogsToTheAuditManager(t *testing.T) {
	_ = ClosePathStatsStore(context.Background())
	dbPath := migratedSQLite(t, "audit_handoff.db")
	if err := InitPathStatsStore("sqlite://"+dbPath, 7); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = ClosePathStatsStore(context.Background()) })
	st := store

	ConfigureGranularRetention(0, 0, 0, 90)

	insert := st.dialect.Rebind(`INSERT INTO audit_logs
		(id, user_id, action, resource, details, timestamp, ip_address, signature, previous_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	old := time.Now().AddDate(0, 0, -120)
	if _, err := st.db.Exec(insert, "old", "admin", "a", "r", "d", old, "203.0.113.7", "s", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}

	st.prune()

	var n int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM audit_logs").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("telemetry prune deleted an audit entry without archiving it; got %d rows, want 1", n)
	}
}
