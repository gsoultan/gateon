// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

type fakeThreatArchiver struct {
	enabled bool
	fail    error
	got     []*SecurityThreat
}

func (f *fakeThreatArchiver) Enabled() bool { return f.enabled }
func (f *fakeThreatArchiver) Archive(_ context.Context, ts []*SecurityThreat) error {
	if f.fail != nil {
		return f.fail
	}
	f.got = append(f.got, ts...)
	return nil
}

// threatPruneStore opens a store with expired threats past a 30-day retention
// and one fresh threat.
func threatPruneStore(t *testing.T, expired int) *pathStatsStore {
	t.Helper()
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore("sqlite://"+filepath.Join(t.TempDir(), "threat_prune.db"), 7); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = ClosePathStatsStore(context.Background()) })
	t.Cleanup(func() { SetThreatArchiver(nil) })
	s := getStore()
	s.securityThreatRetentionDays.Store(30)

	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := s.threatInsertStmt(tx)
	if err != nil {
		t.Fatal(err)
	}
	seed := func(id string, at time.Time) {
		th := &SecurityThreat{ID: id, Type: "sqli", Category: "waf", SourceIP: "203.0.113.5", Time: at, RequestBody: "body-" + id}
		if !s.execThreat(tx, stmt, th, "") {
			t.Fatalf("seed %s failed", id)
		}
	}
	for i := range expired {
		seed(fmt.Sprintf("old-%04d", i), time.Now().AddDate(0, 0, -60).Add(time.Duration(i)*time.Second))
	}
	seed("fresh", time.Now())
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return s
}

func threatCount(t *testing.T, s *pathStatsStore) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM security_threats").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Expired threats were deleted outright. With an archiver installed every one
// of them, bodies included, is handed over before its row goes, across more
// than one chunk.
func TestPruneArchivesExpiredThreatsBeforeDeleting(t *testing.T) {
	s := threatPruneStore(t, threatPruneChunk+5)
	a := &fakeThreatArchiver{enabled: true}
	SetThreatArchiver(a)

	s.pruneSecurityThreats(context.Background())

	if n := threatCount(t, s); n != 1 {
		t.Fatalf("got %d threats left, want only the fresh one", n)
	}
	if len(a.got) != threatPruneChunk+5 {
		t.Fatalf("archived %d threats, want %d", len(a.got), threatPruneChunk+5)
	}
	if a.got[0].ID != "old-0000" || a.got[0].RequestBody != "body-old-0000" {
		t.Fatalf("first archived threat is %+v, want old-0000 with its body, oldest first", a.got[0])
	}
}

// The contract that makes deleting safe: a failed archive deletes nothing.
func TestPruneKeepsThreatsWhenArchivingFails(t *testing.T) {
	s := threatPruneStore(t, 3)
	SetThreatArchiver(&fakeThreatArchiver{enabled: true, fail: errors.New("disk full")})

	s.pruneSecurityThreats(context.Background())

	if n := threatCount(t, s); n != 4 {
		t.Fatalf("got %d threats, want all 4 kept after a failed archive", n)
	}
}

// Archiving off keeps the old behaviour, in chunks: expired threats deleted,
// fresh ones kept, nothing handed to the archiver.
func TestPruneWithArchivingOffOnlyDeletes(t *testing.T) {
	s := threatPruneStore(t, threatPruneChunk+1)
	a := &fakeThreatArchiver{enabled: false}
	SetThreatArchiver(a)

	s.pruneSecurityThreats(context.Background())

	if n := threatCount(t, s); n != 1 {
		t.Fatalf("got %d threats left, want only the fresh one", n)
	}
	if len(a.got) != 0 {
		t.Fatalf("a disabled archiver was handed %d threats", len(a.got))
	}
}
