// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package logger

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Per-request log lines are rate-limited (ADR 0049, ADR 0061). Under the
// packaged unit stdout goes to journald, whose default rate limit -- 10000
// lines in 30 s, about 333 a second -- then drops every line from the service,
// its ERRORs and security events included. A line written once per request,
// or once per refused request, is a line a single client can make the gateway
// write 20000 times a second. The metrics and the trace store count every
// event; the log is what gives.

// countBits is how much of PerSecond's state word holds the count; the rest
// holds the window. 2^24 lines a second is beyond any cap worth setting, and
// 40 bits of seconds is longer than any process lives.
const (
	countBits = 24
	countMask = 1<<countBits - 1
)

// epoch is what PerSecond measures its windows from. A time.Time taken from
// time.Now carries the monotonic clock, so windows measured from it never move
// backwards when the wall clock is stepped.
var epoch = time.Now()

// windowOf is the one-second window now falls in, counted from epoch.
func windowOf(now time.Time) uint64 {
	d := now.Sub(epoch)
	if d < 0 {
		return 0
	}
	return uint64(d / time.Second)
}

// PerSecond admits at most Max events in each one-second window. Its zero
// value admits everything until SetMax is called with a positive cap.
//
// The window and the count of the window share one atomic word, so moving to
// a new window and counting in it are one compare-and-swap: nothing can count
// into a window that is being reset. The window only moves forwards. An event
// stamped earlier than the current window -- a request that started a while
// ago and is only now being logged -- counts against the current window rather
// than reopening its own; the access-log cap used to reopen it, resetting the
// count each time, and let 737 lines a second through a cap of 100.
type PerSecond struct {
	max   atomic.Int64
	state atomic.Uint64
}

// SetMax sets the cap; zero or less lifts it.
func (p *PerSecond) SetMax(n int64) { p.max.Store(n) }

// Max is the cap in force; zero or less means none.
func (p *PerSecond) Max() int64 { return p.max.Load() }

// Allow reports whether one more event may happen at now. It does not
// allocate and takes no lock.
func (p *PerSecond) Allow(now time.Time) bool {
	limit := p.max.Load()
	if limit <= 0 {
		return true
	}
	limit = min(limit, countMask)
	w := windowOf(now)
	for {
		s := p.state.Load()
		cur, n := s>>countBits, s&countMask
		if w > cur {
			if p.state.CompareAndSwap(s, w<<countBits|1) {
				return true
			}
			continue
		}
		if n >= uint64(limit) {
			return false
		}
		if p.state.CompareAndSwap(s, s+1) {
			return true
		}
	}
}

// LineLimiter writes the first lines of one kind of event in each second and
// counts the rest by key, saying how many it left out at most once per
// summary interval, one line per key.
//
// The report is written by the first call after the interval has passed, not
// by a timer: there is no goroutine to stop. A burst's last interval is
// therefore reported when the next event of the same kind happens; the line
// says since when it counted, so a late report is still accurate.
type LineLimiter struct {
	budget  PerSecond
	every   time.Duration
	level   slog.Level
	summary string
	labels  [2]string

	// pendingN is the number of lines counted and not yet reported, read
	// without the lock so an Allow with nothing pending takes none.
	pendingN atomic.Int64

	mu       sync.Mutex
	pending  map[[2]string]int64
	overflow int64
	since    time.Time
}

// lineLimiterMaxKeys bounds the keys a LineLimiter counts under between two
// reports; past it lines are counted under one overflow key. The keys are
// configuration (a route, a rule, a target), not request data, but a bound
// costs nothing and makes the report's size a constant.
const lineLimiterMaxKeys = 32

// LineLimit describes a LineLimiter.
type LineLimit struct {
	// Level is the level the report is written at: the level of the lines it
	// stands for.
	Level slog.Level
	// Summary is the report's message.
	Summary string
	// PerSecond is how many lines are written a second; zero or less writes
	// every line.
	PerSecond int64
	// Every is the least time between two reports.
	Every time.Duration
	// Labels name the two parts of the key lines are counted under.
	Labels [2]string
}

// NewLineLimiter returns a limiter that writes at most c.PerSecond lines a
// second and reports what it left out at most once every c.Every.
func NewLineLimiter(c LineLimit) *LineLimiter {
	l := &LineLimiter{every: c.Every, level: c.Level, summary: c.Summary, labels: c.Labels}
	l.budget.SetMax(c.PerSecond)
	return l
}

// Allow reports whether a line may be written at now. A caller told no must
// call Skip, which counts the line for the next report.
func (l *LineLimiter) Allow(now time.Time) bool {
	if l.pendingN.Load() > 0 {
		l.reportDue(now)
	}
	return l.budget.Allow(now)
}

// Skip counts a line that was not written under the key (a, b).
func (l *LineLimiter) Skip(now time.Time, a, b string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending == nil {
		l.pending = make(map[[2]string]int64, 4)
	}
	if l.since.IsZero() {
		l.since = now
	}
	key := [2]string{a, b}
	if _, ok := l.pending[key]; ok || len(l.pending) < lineLimiterMaxKeys {
		l.pending[key]++
	} else {
		l.overflow++
	}
	l.pendingN.Add(1)
}

// reportDue writes the report when the interval since the first line it
// counts has passed.
func (l *LineLimiter) reportDue(now time.Time) {
	l.mu.Lock()
	if l.since.IsZero() || now.Sub(l.since) < l.every {
		l.mu.Unlock()
		return
	}
	pending, overflow, since := l.pending, l.overflow, l.since
	l.pending, l.overflow, l.since = nil, 0, time.Time{}
	l.pendingN.Store(0)
	l.mu.Unlock()
	l.write(pending, overflow, since)
}

// Flush writes the report now, whatever the interval. For shutdown and tests.
func (l *LineLimiter) Flush() {
	l.mu.Lock()
	pending, overflow, since := l.pending, l.overflow, l.since
	l.pending, l.overflow, l.since = nil, 0, time.Time{}
	l.pendingN.Store(0)
	l.mu.Unlock()
	l.write(pending, overflow, since)
}

// write logs one line per key counted, and one for the overflow.
func (l *LineLimiter) write(pending map[[2]string]int64, overflow int64, since time.Time) {
	lg := L.get()
	ctx := context.Background()
	for key, n := range pending {
		lg.Log(ctx, l.level, l.summary, l.labels[0], key[0], l.labels[1], key[1],
			"not_written", n, "since", since, "max_per_second", l.budget.Max())
	}
	if overflow > 0 {
		lg.Log(ctx, l.level, l.summary, l.labels[0], "(other)", l.labels[1], "(other)",
			"not_written", overflow, "since", since, "max_per_second", l.budget.Max())
	}
}
