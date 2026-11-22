// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/testutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Every audit entry is stored through a PgBouncer in transaction pooling mode.
//
// The manager prepared its insert once, on whichever server connection the
// pooler gave it, and executed it for the life of the process. In transaction
// mode the next execute can land on another server connection, which has never
// seen the statement, and the entry was dropped with "prepared statement "1"
// does not exist" -- after it had already become the previous hash of the next
// one, so the chain read as broken where nothing was tampered with.
//
// It needs a PgBouncer in transaction mode, named by
// GATEON_TEST_PGBOUNCER_DSN, and is skipped without one; CI runs one.
func TestEveryEntryIsStoredThroughTransactionPooling(t *testing.T) {
	dsn := testutil.PgBouncerDSN(t, "needs a PgBouncer in transaction pooling mode")
	database, dialect, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	const user = "pgbouncer-transaction-pooling-test"
	clear := func() {
		_, _ = database.Exec(dialect.Rebind("DELETE FROM audit_logs WHERE user_id = ?"), user)
	}
	clear()
	t.Cleanup(clear)

	m := newAuditManager(&gateonv1.AuditConfig{Enabled: true}, database, dialect)
	const workers, perWorker = 8, 50
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				m.log(context.Background(), user, "update", "global_config", "change", "198.51.100.7")
			}
		}()
	}
	wg.Wait()

	var stored int
	q := dialect.Rebind("SELECT COUNT(*) FROM audit_logs WHERE user_id = ?")
	if err := database.QueryRow(q, user).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != workers*perWorker {
		t.Fatalf("%d of %d audit entries stored through the pooler", stored, workers*perWorker)
	}
}
