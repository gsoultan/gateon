// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry/pathbudget"
	"github.com/gsoultan/gateon/internal/testutil"
)

// onEachRetentionEngine runs test against a store on SQLite and, when
// GATEON_TEST_POSTGRES_DSN is set, on Postgres.
func onEachRetentionEngine(t *testing.T, test func(t *testing.T, s *pathStatsStore)) {
	t.Run("sqlite", func(t *testing.T) {
		test(t, openRetentionStore(t, "sqlite://"+migratedSQLite(t, "retention.db")))
	})
	t.Run("postgres", func(t *testing.T) {
		test(t, openRetentionStore(t, testutil.PostgresDSN(t, "skipping the Postgres run")))
	})
}

func openRetentionStore(t *testing.T, databaseURL string) *pathStatsStore {
	t.Helper()
	t.Setenv("GATEON_TRACE_DIR", t.TempDir())
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(databaseURL, 1); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = ClosePathStatsStore(context.Background()) })
	s := getStore()
	clear := func() {
		for _, table := range []string{"ip_mitigations", "path_stats"} {
			_, _ = s.db.Exec("DELETE FROM " + table)
		}
	}
	clear()
	t.Cleanup(clear) // a shared Postgres keeps rows across tests
	return s
}

// Nothing pruned ip_mitigations, so it kept a row for every address ever
// shunned automatically. A shun that lapsed past the ladder's memory and a
// release past its hold are read by nothing, and now go; everything a
// decision still reads stays.
func TestSpentAddressShunsArePruned(t *testing.T) {
	onEachRetentionEngine(t, func(t *testing.T, s *pathStatsStore) {
		now := time.Now()
		ago := func(d time.Duration) string { return sqlUTC(now.Add(-d)) }
		ins := s.dialect.Rebind(`INSERT INTO ip_mitigations (ip, status, reason, mitigated_at, expires_at, unmitigated_at, updated_at)
			VALUES (?, ?, 'test', ?, ?, ?, CURRENT_TIMESTAMP)`)
		rows := []struct {
			ip, status       string
			expires, release any
			kept             bool
		}{
			{"192.0.2.1", statusMitigated, ago(autoShunMemory + time.Hour), nil, false}, // lapsed, forgotten by the ladder
			{"192.0.2.2", statusMitigated, ago(time.Hour), nil, true},                   // lapsed, the ladder still reads it
			{"192.0.2.3", statusMitigated, sqlUTC(now.Add(time.Hour)), nil, true},       // in force
			{"192.0.2.4", statusMitigated, nil, nil, true},                              // an operator's block
			{"192.0.2.5", statusUnmitigated, nil, ago(ipReleaseHold + time.Hour), false}, // release past its hold
			{"192.0.2.6", statusUnmitigated, nil, ago(time.Hour), true},                  // release still held
		}
		for _, r := range rows {
			if _, err := s.db.Exec(ins, r.ip, r.status, ago(48*time.Hour), r.expires, r.release); err != nil {
				t.Fatalf("insert %s: %v", r.ip, err)
			}
		}

		s.pruneSpentIPShuns(context.Background(), now)

		for _, r := range rows {
			var n int
			if err := s.db.QueryRow(s.dialect.Rebind(`SELECT COUNT(*) FROM ip_mitigations WHERE ip = ?`), r.ip).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if kept := n == 1; kept != r.kept {
				t.Errorf("%s (%s): kept=%v, want %v", r.ip, r.status, kept, r.kept)
			}
		}
	})
}

// Retention deleted path_stats past the window in one DELETE, holding
// SQLite's write lock for the whole backlog. It now deletes a chunk per
// statement; this checks the chunks between them still delete all of it and
// nothing inside the window.
func TestRetentionDeletesEveryChunkAndOnlyExpiredRows(t *testing.T) {
	onEachRetentionEngine(t, func(t *testing.T, s *pathStatsStore) {
		const expired = 2*pruneChunk + 17
		old := time.Now().AddDate(0, 0, -30).UTC().Format("2006-01-02")
		today := time.Now().UTC().Format("2006-01-02")
		tx, err := s.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		ins := s.dialect.Rebind(`INSERT INTO path_stats (day, host, path, req_count, latency_sum_s, bytes_total) VALUES (?, 'h', ?, 1, 0, 0)`)
		for i := range expired {
			if _, err := tx.Exec(ins, old, "/"+strconv.Itoa(i)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tx.Exec(ins, today, "/kept"); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		s.pathStatsRetentionDays.Store(7)

		s.prunePathAndDomainStats(context.Background())

		var left, kept int
		_ = s.db.QueryRow(s.dialect.Rebind(`SELECT COUNT(*) FROM path_stats WHERE day = ?`), old).Scan(&left)
		_ = s.db.QueryRow(s.dialect.Rebind(`SELECT COUNT(*) FROM path_stats WHERE day = ?`), today).Scan(&kept)
		if left != 0 || kept != 1 {
			t.Fatalf("after the prune: %d expired rows left (want 0), %d current rows (want 1)", left, kept)
		}
	})
}

// path_stats kept a row per distinct path a client asked for, so a scanner
// grew it by a row a request. The day's paths past the host's budget are now
// counted in one overflow row, and no request goes uncounted.
func TestAScannerCannotGrowPathStatsPastItsBudget(t *testing.T) {
	t.Setenv(pathbudget.EnvMaxPathsPerHost, "10")
	t.Setenv(pathbudget.EnvMaxRowsPerDay, "100")
	onEachRetentionEngine(t, func(t *testing.T, s *pathStatsStore) {
		const host, requests = "scanned.example", 1000
		now := time.Now()
		batch := make([]increment, 0, requests)
		for i := range requests {
			batch = append(batch, increment{host: host, path: fmt.Sprintf("/probe/%d", i), latS: 0.001, bytesTotal: 1, atTime: now})
		}
		s.flushIncrements(batch[:requests/2])
		s.flushIncrements(batch[requests/2:])

		var rows, counted int
		q := s.dialect.Rebind(`SELECT COUNT(*), COALESCE(SUM(req_count), 0) FROM path_stats WHERE host = ?`)
		if err := s.db.QueryRow(q, host).Scan(&rows, &counted); err != nil {
			t.Fatal(err)
		}
		if rows > 11 {
			t.Errorf("%d distinct paths made %d rows under a budget of 10 per host", requests, rows)
		}
		if counted != requests {
			t.Errorf("path_stats counts %d requests, want all %d", counted, requests)
		}
	})
}

// A restart starts a new budget. It is seeded from the day's stored rows, so
// it does not grant the day a second budget's worth of rows.
func TestARestartDoesNotGrantTheDayASecondPathBudget(t *testing.T) {
	t.Setenv(pathbudget.EnvMaxPathsPerHost, "10")
	t.Setenv(pathbudget.EnvMaxRowsPerDay, "100")
	databaseURL := "sqlite://" + migratedSQLite(t, "restart.db")
	now := time.Now()
	flushPaths := func(from, to int) {
		s := openRetentionStore(t, databaseURL)
		batch := make([]increment, 0, to-from)
		for i := from; i < to; i++ {
			batch = append(batch, increment{host: "h.example", path: fmt.Sprintf("/p/%d", i), atTime: now})
		}
		s.flushIncrements(batch)
	}
	flushPaths(0, 10)
	// openRetentionStore empties path_stats, so reopen by hand for the restart.
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(databaseURL, 1); err != nil {
		t.Fatal(err)
	}
	s := getStore()
	batch := make([]increment, 0, 10)
	for i := 10; i < 20; i++ {
		batch = append(batch, increment{host: "h.example", path: fmt.Sprintf("/p/%d", i), atTime: now})
	}
	s.flushIncrements(batch)
	var rows int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM path_stats WHERE host = 'h.example'`).Scan(&rows)
	if rows > 11 {
		t.Fatalf("after a restart the host has %d rows under a budget of 10", rows)
	}
}
