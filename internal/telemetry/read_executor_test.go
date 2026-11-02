// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
)

// A dashboard read on Postgres opened a read-only transaction around its one
// statement: a BEGIN and a ROLLBACK round trip per read that isolated
// nothing. The read now goes to the pool, on both engines.
func TestADashboardReadIsOneStatementOnPostgres(t *testing.T) {
	openRetentionStore(t, testutil.PostgresDSN(t, "skipping the Postgres run"))
	s := getStore()
	ex, cleanup := s.getExecutor(context.Background())
	defer cleanup()
	if ex != queryExecutor(s.db) {
		t.Fatalf("a read on %s goes through %T, not the pool", s.dialect.Driver, ex)
	}
}
