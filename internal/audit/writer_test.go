// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/testutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// installWriter starts m's system-entry writer as Init does, installs m as the
// package manager for LogSystem and Flush, and stops both at cleanup.
func installWriter(t *testing.T, m *AuditManager) {
	t.Helper()
	m.startWriter()
	prev := manager
	manager = m
	t.Cleanup(func() {
		close(m.stop)
		<-m.writerDone
		manager = prev
	})
}

// The telemetry writer logged every threat through log, an INSERT it waited
// for. With the audit table's write lock held -- by a retention delete, a
// checkpoint, another writer -- every threat waited the busy timeout, and the
// threats behind it were dropped when their channel filled. LogSystem only
// queues: it returns while the lock is still held, and the entries are stored
// once it is released.
func TestSystemEntriesDoNotWaitForTheDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit_lock.db")
	conn, dialect, err := db.Open("sqlite:" + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(conn, dialect); err != nil {
		t.Fatal(err)
	}
	m := &AuditManager{
		config: signingConfig(testKey), db: conn, dialect: dialect,
		Broadcaster: &Broadcaster{subscribers: map[chan AuditEntry]struct{}{}},
		stop:        make(chan struct{}),
	}
	installWriter(t, m)

	// A second pool on the same file takes the write lock and holds it.
	other, _, err := db.Open("sqlite:" + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	lock, err := other.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.Exec(`DELETE FROM audit_logs WHERE id = 'none'`); err != nil {
		t.Fatal(err)
	}

	const n = 100
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range n {
			LogSystem("threat", "/probe/"+strconv.Itoa(i), "details", "192.0.2.1")
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = lock.Rollback()
		t.Fatal("LogSystem waited for the database's write lock")
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}

	Flush()
	entries := readChain(t, m)
	if len(entries) != n {
		t.Fatalf("%d of %d system entries stored", len(entries), n)
	}
	if err := VerifyChain(entries, testKey, ""); err != nil {
		t.Fatalf("the stored chain does not verify: %v", err)
	}
}

// System entries are signed when they are written and operator entries when
// they are logged, from the same chain. However the two interleave, what is
// stored reads back, in timestamp order, as one chain that verifies -- on
// Postgres too, which keeps microseconds, so a batch signed inside one
// microsecond must not read back out of order.
func TestSystemAndOperatorEntriesShareOneChain(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		m := newTestManager(t, signingConfig(testKey))
		assertOneChain(t, m)
	})
	t.Run("postgres", func(t *testing.T) {
		conn, dialect, err := db.Open(testutil.PostgresDSN(t, "skipping the Postgres run"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := db.Migrate(conn, dialect); err != nil {
			t.Fatal(err)
		}
		clear := func() { _, _ = conn.Exec(`DELETE FROM audit_logs`) }
		clear()
		t.Cleanup(clear)
		m := &AuditManager{
			config: signingConfig(testKey), db: conn, dialect: dialect,
			Broadcaster: &Broadcaster{subscribers: map[chan AuditEntry]struct{}{}},
			stop:        make(chan struct{}),
		}
		m.prepareStatements()
		assertOneChain(t, m)
	})
}

func assertOneChain(t *testing.T, m *AuditManager) {
	t.Helper()
	installWriter(t, m)
	const each = 300
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range each {
			LogSystem("threat", "/"+strconv.Itoa(i), "d", "192.0.2.1")
		}
	})
	wg.Go(func() {
		for i := range each / 10 {
			m.log(context.Background(), "admin", "update", "route/"+strconv.Itoa(i), "d", "127.0.0.1")
		}
	})
	wg.Wait()
	Flush()

	entries := readChain(t, m)
	if len(entries) != each+each/10 {
		t.Fatalf("%d entries stored, want %d", len(entries), each+each/10)
	}
	if err := VerifyChain(entries, testKey, ""); err != nil {
		t.Fatalf("the chain does not verify: %v", err)
	}
}

// A disabled audit log records no system entries either.
func TestSystemEntriesRespectAuditOff(t *testing.T) {
	m := newTestManager(t, &gateonv1.AuditConfig{Enabled: false})
	installWriter(t, m)
	LogSystem("threat", "/", "d", "192.0.2.1")
	Flush()
	if got := readChain(t, m); len(got) != 0 {
		t.Fatalf("%d entries stored with auditing off", len(got))
	}
}

// Stop stores what is still queued before it returns, so a shutdown does not
// lose the entries the writer had not got to.
func TestStopStoresTheQueuedEntries(t *testing.T) {
	m := newTestManager(t, signingConfig(testKey))
	m.startWriter()
	prev := manager
	manager = m
	t.Cleanup(func() { manager = prev })
	for i := range 50 {
		LogSystem("threat", "/"+strconv.Itoa(i), "d", "192.0.2.1")
	}
	Stop()
	if got := readChain(t, m); len(got) != 50 {
		t.Fatalf("%d of 50 queued entries stored after Stop", len(got))
	}
}
