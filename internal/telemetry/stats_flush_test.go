// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/testutil"
)

// TestOneRequestCannotAbortATrafficStatsFlush.
//
// Path and domain counters are flushed in one transaction, one upsert per
// bucket. Postgres refuses a TEXT value containing NUL or invalid UTF-8, and
// domain_stats.domain is VARCHAR(255) there -- and a request supplies all
// three: %00 and %FF decode into r.URL.Path, and nothing bounds the Host that
// RecordDomainRequest passes through. One refused upsert aborts a Postgres
// transaction, every later statement in it fails, and the commit rolls the
// whole flush back. So a single request per flush interval erased every
// counter the gateway had gathered since the last one: the traffic charts, the
// path table and "Requests Today" went blind on request.
func TestOneRequestCannotAbortATrafficStatsFlush(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		assertFlushSurvivesHostileRequest(t, "sqlite://"+filepath.Join(t.TempDir(), "flush.db"))
	})
	t.Run("postgres", func(t *testing.T) {
		assertFlushSurvivesHostileRequest(t, testutil.PostgresDSN(t, "skipping the Postgres run"))
	})
}

func assertFlushSurvivesHostileRequest(t *testing.T, databaseURL string) {
	t.Helper()
	t.Setenv("GATEON_TRACE_DIR", t.TempDir())
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(databaseURL, 1); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer func() { _ = ClosePathStatsStore(context.Background()) }()

	s := getStore()
	host := fmt.Sprintf("flush-%d.example", time.Now().UnixNano())
	longHost := strings.Repeat("h", 300) + ".example"
	defer func() {
		_, _ = s.db.Exec(s.dialect.Rebind("DELETE FROM path_stats WHERE host = ?"), host)
		// The long Host may be stored cut short, so match it by prefix.
		_, _ = s.db.Exec(s.dialect.Rebind("DELETE FROM domain_stats WHERE domain = ? OR domain LIKE ?"),
			host, longHost[:40]+"%")
	}()

	now := time.Now()
	s.flushIncrements([]increment{
		{host: host, path: "/ok", latS: 0.01, bytesTotal: 100, atTime: now},
		{host: host, path: "/ok", latS: 0.01, bytesTotal: 100, atTime: now},
		{host: host, path: "/a\x00b", latS: 0.01, bytesTotal: 100, atTime: now},
		{host: host, path: "/caf\xff", latS: 0.01, bytesTotal: 100, atTime: now},
		{host: host, latS: 0.01, bytesTotal: 100, atTime: now, isDomain: true},
		{host: longHost, latS: 0.01, bytesTotal: 100, atTime: now, isDomain: true},
	})

	var pathCount, domainCount int64
	_ = s.db.QueryRow(s.dialect.Rebind("SELECT COALESCE(SUM(req_count), 0) FROM path_stats WHERE host = ? AND path = ?"),
		host, "/ok").Scan(&pathCount)
	_ = s.db.QueryRow(s.dialect.Rebind("SELECT COALESCE(SUM(req_count), 0) FROM domain_stats WHERE domain = ?"),
		host).Scan(&domainCount)
	if pathCount != 2 || domainCount != 1 {
		t.Errorf("on %s, after a flush containing a hostile path and Host: %s /ok counted %d (want 2), "+
			"domain counted %d (want 1) -- the ordinary requests in the flush were lost with it",
			s.dialect.Driver, host, pathCount, domainCount)
	}
}

// TestDomainStatsRowsAreBoundedByDistinctHosts.
//
// The Host header is chosen by the client, and RecordDomainRequest persisted it
// raw: every distinct value was a new domain_stats row per half-hour bucket, at
// whatever length the client sent, and every heavy dashboard snapshot then read
// them all back -- GetDomainStatsWindow has no LIMIT -- twice. The Prometheus
// label for the same value was already capped at maxDistinctDomains; the table
// behind it was not.
func TestDomainStatsRowsAreBoundedByDistinctHosts(t *testing.T) {
	freshStore(t)
	s := getStore()

	const sent = maxDistinctDomains + 500
	now := time.Now()
	batch := make([]increment, 0, sent)
	for i := range sent {
		batch = append(batch, increment{
			host: fmt.Sprintf("h%d.attacker.example", i), latS: 0.001, bytesTotal: 1, atTime: now, isDomain: true,
		})
	}
	s.flushIncrements(batch)

	var rows, requests int64
	if err := s.db.QueryRow("SELECT COUNT(*), COALESCE(SUM(req_count), 0) FROM domain_stats").Scan(&rows, &requests); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows > maxDistinctDomains+1 {
		t.Errorf("%d distinct Host values produced %d domain_stats rows; the bound is %d plus one overflow row",
			sent, rows, maxDistinctDomains)
	}
	if requests != sent {
		t.Errorf("the bound lost requests: %d counted, %d sent", requests, sent)
	}
}

// TestTrafficStatsAccumulateAcrossFlushesOnEveryEngine flushes the same path
// and domain twice and requires the second flush to add to the first -- the ON
// CONFLICT DO UPDATE half of the upsert, which a single flush never reaches.
//
// On Postgres that half named its columns unqualified, which Postgres refuses as
// ambiguous at prepare time; the error was discarded, so no path or domain
// statistic was ever stored on a Postgres deployment: the traffic charts, the
// path table and "Requests Today" were empty from the first day.
func TestTrafficStatsAccumulateAcrossFlushesOnEveryEngine(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		assertStatsAccumulate(t, "sqlite://"+filepath.Join(t.TempDir(), "accumulate.db"))
	})
	t.Run("postgres", func(t *testing.T) {
		assertStatsAccumulate(t, testutil.PostgresDSN(t, "skipping the Postgres run"))
	})
}

func assertStatsAccumulate(t *testing.T, databaseURL string) {
	t.Helper()
	t.Setenv("GATEON_TRACE_DIR", t.TempDir())
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(databaseURL, 1); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer func() { _ = ClosePathStatsStore(context.Background()) }()

	s := getStore()
	host := fmt.Sprintf("accumulate-%d.example", time.Now().UnixNano())
	defer func() {
		_, _ = s.db.Exec(s.dialect.Rebind("DELETE FROM path_stats WHERE host = ?"), host)
		_, _ = s.db.Exec(s.dialect.Rebind("DELETE FROM domain_stats WHERE domain = ?"), host)
	}()
	now := time.Now()
	for range 2 {
		s.flushIncrements([]increment{
			{host: host, path: "/x", latS: 0.5, bytesTotal: 10, atTime: now},
			{host: host, latS: 0.5, bytesTotal: 10, atTime: now, isDomain: true},
		})
	}

	var pathCount, pathBytes, domainCount int64
	if err := s.db.QueryRow(s.dialect.Rebind("SELECT COALESCE(SUM(req_count), 0), COALESCE(SUM(bytes_total), 0) FROM path_stats WHERE host = ? AND path = ?"),
		host, "/x").Scan(&pathCount, &pathBytes); err != nil {
		t.Fatalf("read path_stats: %v", err)
	}
	if err := s.db.QueryRow(s.dialect.Rebind("SELECT COALESCE(SUM(req_count), 0) FROM domain_stats WHERE domain = ?"),
		host).Scan(&domainCount); err != nil {
		t.Fatalf("read domain_stats: %v", err)
	}
	if pathCount != 2 || pathBytes != 20 || domainCount != 2 {
		t.Errorf("on %s after two flushes: path req_count=%d bytes=%d, domain req_count=%d; want 2, 20, 2",
			s.dialect.Driver, pathCount, pathBytes, domainCount)
	}
}
