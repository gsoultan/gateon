// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package tracebudget bounds the disk the live trace store may use, and keeps
// it from filling the disk it shares with everything else (ADR 0049).
//
// The trace store was bounded by age alone: about 1.1 KB a request for seven
// days on the standard profile, which is some 66 GB at an average of 100
// requests a second and nothing at all to an attacker who sends more. On the
// full disk that followed, Pebble retried the compaction that had just failed
// at once and for ever -- about two cores of CPU on an idle gateway -- logged
// each failure at INFO, and /readyz still said ready.
//
// Three bounds answer that, each owned here and wired by the store:
//
//   - a size budget, per profile (GATEON_TRACE_STORE_MAX_MB overrides), past
//     which the oldest traces are evicted whatever their age;
//   - a free-space floor on the disk itself, below which trace writes stop --
//     counted in gateon_trace_dropped_total and logged at ERROR at most once a
//     minute -- until space comes back, and /readyz says so;
//   - a backoff on Pebble creating files after the disk reported it is full,
//     so a failing compaction is retried once a backoff period rather than in
//     a loop.
package tracebudget

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
)

// EnvMaxMB overrides the profile's trace store budget, in MiB. A value that
// is not a positive integer is ignored, as the trace archive's variables are.
const EnvMaxMB = "GATEON_TRACE_STORE_MAX_MB"

// MaxBytes is the most disk the live trace store may use: GATEON_TRACE_STORE_MAX_MB
// when it is a positive integer, else the profile's TraceStoreMaxBytes.
func MaxBytes(td config.TierDefaults) int64 {
	if mb, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(EnvMaxMB)), 10, 64); err == nil && mb > 0 {
		return mb << 20
	}
	return td.TraceStoreMaxBytes
}

// The free-space floor: a twentieth of the filesystem, but never less than
// floorMemtables memtables -- what Pebble needs to flush what it already holds
// and compact it -- and never more than maxFloor, which is room enough on any
// disk for that.
const (
	floorMemtables = 4
	maxFloor       = 1 << 30
)

// Floor is how much of a filesystem of total bytes must stay free for the
// trace store to keep writing, given its memtable size.
func Floor(total uint64, memtable int64) uint64 {
	floor := total / 20
	if lowest := uint64(max(memtable, 1<<20)) * floorMemtables; floor < lowest {
		floor = lowest
	}
	return min(floor, maxFloor)
}

// EvictionTarget is how far below the budget an eviction brings the store, so
// the next one is not due a moment later: four fifths of it.
func EvictionTarget(budget int64) uint64 {
	return uint64(budget) / 5 * 4
}

// FindCutoff returns the earliest time in [oldest, newest] such that the
// traces before it take at least need bytes, by bisecting on below, which
// estimates the bytes the traces before a time take. It returns newest when
// even everything is not enough. Keys sort by time, so below is monotonic;
// precision is a millisecond, far finer than a trace store's hour of traffic.
func FindCutoff(oldest, newest time.Time, need uint64, below func(time.Time) uint64) time.Time {
	lo, hi := oldest, newest
	for hi.Sub(lo) > time.Millisecond {
		mid := lo.Add(hi.Sub(lo) / 2)
		if below(mid) >= need {
			hi = mid
		} else {
			lo = mid
		}
	}
	return hi
}
