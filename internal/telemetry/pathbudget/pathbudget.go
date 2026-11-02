// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package pathbudget bounds the rows path_stats gains in a day.
//
// path_stats keeps one row per day, host and path, and the path is whatever
// the client asked for. A scanner walking random paths added a row for every
// request it made, and the dashboard's top-paths read and the hourly prune
// paid for every one of them. A Budget admits the first paths a host is seen
// with each day, up to a per-host and a per-day ceiling, and folds the rest
// into one Overflow row per host -- or, once the day's ceiling is reached, into
// a single Overflow host and path. Counts are never dropped, only folded, so
// every total the dashboard computes from path_stats stays right.
//
// Like the domain labels, it never evicts: eviction would let a scanner push
// out the paths an operator watches, and the first paths a day sees are, in
// practice, the configured traffic.
package pathbudget

import (
	"hash/maphash"
	"os"
	"strconv"
	"strings"
)

// Overflow is the path, and past the day's ceiling the host, that the paths
// over budget are counted under.
const Overflow = "other"

// The environment variables that override the tier's ceilings.
const (
	EnvMaxPathsPerHost = "GATEON_PATH_STATS_MAX_PATHS_PER_HOST"
	EnvMaxRowsPerDay   = "GATEON_PATH_STATS_MAX_ROWS_PER_DAY"
)

// Limits is how many rows a day may gain.
type Limits struct {
	// PathsPerHost is how many distinct paths one host keeps as themselves.
	PathsPerHost int
	// RowsPerDay is how many rows the whole day keeps.
	RowsPerDay int
}

// WithEnv returns l with each environment override that is set and valid. A
// malformed or non-positive one is ignored, so a typo does not lift a bound.
func (l Limits) WithEnv() Limits {
	if n, ok := positiveEnv(EnvMaxPathsPerHost); ok {
		l.PathsPerHost = n
	}
	if n, ok := positiveEnv(EnvMaxRowsPerDay); ok {
		l.RowsPerDay = n
	}
	return l
}

func positiveEnv(name string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	return n, err == nil && n > 0
}

// Budget is one store's admissions. It is not safe for concurrent use: the
// telemetry writer, its only user, is one goroutine.
type Budget struct {
	limits Limits
	seed   maphash.Seed
	days   map[string]*day
}

// day is one day's admissions. Rows are kept as a hash of host and path, not
// the text: eight bytes a row however long the path.
type day struct {
	rows    map[uint64]struct{}
	perHost map[string]int
}

// New returns an empty budget held to limits.
func New(limits Limits) *Budget {
	return &Budget{limits: limits, seed: maphash.MakeSeed(), days: make(map[string]*day, 2)}
}

// Known reports whether the budget holds day at all. The writer seeds a day
// it does not know from the rows already stored, so a restart does not grant
// the day a second budget.
func (b *Budget) Known(d string) bool {
	_, ok := b.days[d]
	return ok
}

// Open makes day d known with nothing admitted, for a writer whose seed read
// failed: it starts the day from its own admissions rather than retrying the
// read on every flush.
func (b *Budget) Open(d string) { b.day(d) }

// Seed records a row already stored for day d. It counts against the budget
// like an admission, even past it: the row exists.
func (b *Budget) Seed(d, host, path string) {
	b.day(d).add(b.key(host, path), host)
}

// Admit returns the host and path a request for host and path on day d is
// counted under: themselves while the budget allows, else an Overflow row.
func (b *Budget) Admit(d, host, path string) (string, string) {
	dd := b.day(d)
	k := b.key(host, path)
	if _, ok := dd.rows[k]; ok {
		return host, path
	}
	switch {
	case len(dd.rows) >= b.limits.RowsPerDay:
		host, path = Overflow, Overflow
	case dd.perHost[host] >= b.limits.PathsPerHost:
		path = Overflow
	default:
		dd.add(k, host)
		return host, path
	}
	// The overflow row is a row too. It is admitted past the ceiling, once:
	// the counts it carries have nowhere else to go.
	if k := b.key(host, path); !dd.has(k) {
		dd.add(k, host)
	}
	return host, path
}

// day returns d's admissions, creating them. Only the two newest days are
// kept: a batch spans midnight at most, and an older day is never written
// again.
func (b *Budget) day(d string) *day {
	if dd, ok := b.days[d]; ok {
		return dd
	}
	for len(b.days) >= 2 {
		oldest := ""
		for k := range b.days {
			if oldest == "" || k < oldest {
				oldest = k
			}
		}
		delete(b.days, oldest)
	}
	dd := &day{rows: make(map[uint64]struct{}), perHost: make(map[string]int)}
	b.days[d] = dd
	return dd
}

func (b *Budget) key(host, path string) uint64 {
	var h maphash.Hash
	h.SetSeed(b.seed)
	_, _ = h.WriteString(host)
	_ = h.WriteByte(0)
	_, _ = h.WriteString(path)
	return h.Sum64()
}

func (d *day) has(k uint64) bool {
	_, ok := d.rows[k]
	return ok
}

func (d *day) add(k uint64, host string) {
	d.rows[k] = struct{}{}
	d.perHost[host]++
}

// SeedLimit is the most stored rows of one day worth reading to seed it:
// one more than the day may hold.
func (b *Budget) SeedLimit() int { return b.limits.RowsPerDay + 1 }
