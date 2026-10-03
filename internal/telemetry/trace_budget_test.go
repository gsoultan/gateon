// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeTraces writes n traces of about size bytes each, the first at start
// and one a second after it, the way the store's loop flushes them.
func writeTraces(t *testing.T, s *pathStatsStore, start time.Time, n, size int) {
	t.Helper()
	body := make([]byte, size*3/4)
	batch := make([]*TraceRecord, 0, 256)
	for i := range n {
		if _, err := rand.Read(body); err != nil {
			t.Fatal(err)
		}
		tr := GetTraceRecord()
		tr.ID = fmt.Sprintf("budget-%06d", i)
		tr.Timestamp = start.Add(time.Duration(i) * time.Second)
		tr.Path = "/budget"
		// Random, so compression cannot make the store smaller than the test
		// means it to be.
		tr.RequestBody = base64.StdEncoding.EncodeToString(body)
		batch = append(batch, tr)
		if len(batch) == cap(batch) {
			batch = s.flushTraces(batch)
		}
	}
	s.flushTraces(batch)
	if err := s.pebble.Flush(); err != nil {
		t.Fatal(err)
	}
}

// TestTheTraceStoreIsHeldToItsSizeBudget: the trace store was bounded by age
// alone, so traffic decided how much disk it took -- ~1.1 KB a request for
// seven days -- until the disk was full. Over its budget, the hourly prune
// evicts the oldest traces whatever their age, and keeps the newest.
func TestTheTraceStoreIsHeldToItsSizeBudget(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "standard")
	t.Setenv("GATEON_TRACE_STORE_MAX_MB", "1")
	freshStore(t)
	s := getStore()

	start := time.Now().Add(-2 * time.Hour) // well inside the 7-day retention
	const n = 3000                          // ~6 MB of 2 KB traces, six times the budget
	writeTraces(t, s, start, n, 2048)
	newest := start.Add((n - 1) * time.Second)

	s.prune()

	oldest, found, err := firstTraceTime(t.Context(), s.pebble.NewIter)
	if err != nil || !found {
		t.Fatalf("no traces left after the prune: found=%v err=%v", found, err)
	}
	if !oldest.After(start) {
		t.Errorf("the store holds ~6 MB against a 1 MiB budget and the prune kept the oldest trace (%v)", oldest)
	}
	if GetTrace(newest, fmt.Sprintf("budget-%06d", n-1)) == nil {
		t.Error("the newest trace was evicted; only the oldest should go")
	}
	all, err := s.pebble.EstimateDiskUsage(make([]byte, 8), binary.BigEndian.AppendUint64(nil, uint64(time.Now().UnixNano())))
	if err != nil {
		t.Fatal(err)
	}
	if all > 1<<20 {
		t.Errorf("the traces take %d bytes after the prune, over the 1 MiB budget", all)
	}
}

// TestATraceStoreUnderItsBudgetKeepsEverything is the control: under budget,
// the size bound evicts nothing.
func TestATraceStoreUnderItsBudgetKeepsEverything(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "standard")
	t.Setenv("GATEON_TRACE_STORE_MAX_MB", "64")
	freshStore(t)
	s := getStore()
	start := time.Now().Add(-2 * time.Hour)
	writeTraces(t, s, start, 200, 2048)

	s.prune()

	if GetTrace(start, "budget-000000") == nil {
		t.Error("the oldest trace was evicted from a store well under its budget")
	}
}

// TestTraceStoreNotReadySaysWhyTheStoreStoppedWriting: what /readyz reports
// for the trace store is the guard's reason, and nothing while it writes.
func TestTraceStoreNotReadySaysWhyTheStoreStoppedWriting(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "standard")
	freshStore(t)
	if r := TraceStoreNotReady(); r != "" {
		t.Fatalf("TraceStoreNotReady() = %q on a store with room, want none", r)
	}
	getStore().traceGuard.BackgroundError(fmt.Errorf("write 000001.log: %w", syscall.ENOSPC))
	if r := TraceStoreNotReady(); !strings.Contains(r, "no space left") {
		t.Errorf("TraceStoreNotReady() = %q after ENOSPC, want the reason", r)
	}
}
