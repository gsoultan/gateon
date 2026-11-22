// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
)

// Queries with arguments survive a PgBouncer in transaction pooling mode, the
// pooler that commonly listens on 6432 in front of a managed Postgres.
//
// lib/pq sent a query with arguments in two round trips -- parse and describe,
// then bind and execute -- each closed by a Sync. Between two Syncs outside a
// transaction PgBouncer may hand the client's next message to a different
// server connection, where the unnamed statement the first round trip parsed
// does not exist, so a share of queries failed with "pq: unnamed prepared
// statement does not exist" as soon as two clients were busy at once: the
// block list's first read after the wizard set the gateway up on one did. One
// client alone usually gets the same server back, so the test runs many.
//
// It needs a PgBouncer in transaction mode, named by
// GATEON_TEST_PGBOUNCER_DSN, and is skipped without one; CI runs one.
func TestQueriesWithArgumentsSurviveTransactionPooling(t *testing.T) {
	dsn := testutil.PgBouncerDSN(t, "needs a PgBouncer in transaction pooling mode")
	conn, _, err := Open(dsn)
	if err != nil {
		t.Fatalf("open through the pooler: %v", err)
	}
	defer func() { _ = conn.Close() }()
	conn.SetMaxOpenConns(16)

	const workers, perWorker = 16, 200
	errs := make(chan error, workers*perWorker)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWorker {
				var got int
				if err := conn.QueryRow("SELECT $1::int + $2::int", w, i).Scan(&got); err != nil {
					errs <- err
					continue
				}
				if got != w+i {
					t.Errorf("SELECT %d + %d = %d", w, i, got)
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	failed, first := 0, error(nil)
	for err := range errs {
		if first == nil {
			first = err
		}
		failed++
	}
	if failed > 0 {
		t.Fatalf("%d of %d queries failed through the pooler; first: %v", failed, workers*perWorker, first)
	}
}
