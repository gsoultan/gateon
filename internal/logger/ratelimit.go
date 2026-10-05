// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package logger

import (
	"hash/maphash"
	"log/slog"
	"math/bits"
	"runtime"
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
// backwards when the wall clock is stepped. epochOffset starts the windows on
// the wall clock's second at start-up, so a window is the second a log line's
// timestamp shows: windows offset from it let one timestamped second hold the
// tail of one window and the head of the next, twice the cap, as measured.
var (
	epoch       = time.Now()
	epochOffset = time.Duration(epoch.Nanosecond())
)

// windowOf is the one-second window now falls in, counted from epoch.
func windowOf(now time.Time) uint64 {
	d := now.Sub(epoch) + epochOffset
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
// The report is written by the first call after the interval has passed, and,
// for a registered limiter, by ReportDue, which the server's periodic task
// calls: without it a burst's last interval would be reported only when the
// next event of the same kind happened. The line says since when it counted.
// The limiter starts no goroutine of its own.
//
// Nothing here takes a lock. Skip runs once per refused request past the
// per-second budget -- every WAF block and every failed proxied request under
// attack -- and a mutex there serialised every core on the one limiter exactly
// when the gateway was busiest (review 3, F4). Lines are counted in a
// skipTable with atomics; a report swaps in an empty table and reads the old.
type LineLimiter struct {
	budget  PerSecond
	every   time.Duration
	level   slog.Level
	summary string
	labels  [2]string

	// counts is the table lines are counted in until the next report.
	counts atomic.Pointer[skipTable]
}

// lineLimiterMaxKeys bounds the keys a LineLimiter counts under between two
// reports; past it lines are counted under one overflow key. The keys are
// configuration, not request data -- a WAF rule id and route id, a route id
// and a backend target URL -- so no client can choose one, but a bound costs
// nothing and makes the table, and the report, a constant size: at most two
// tables (the one counting and one being reported) of 32 slots each.
const lineLimiterMaxKeys = 32

// skipTable counts the lines one LineLimiter left out between two reports.
//
// Each of up to lineLimiterMaxKeys keys claims a slot by compare-and-swap,
// probing from the key's hash, and keeps it for the table's life; lines past
// that count under overflow. writers is the number of Skips inside the table:
// a report that has swapped it out reads it only once they have left, so no
// count is lost to the swap.
type skipTable struct {
	slots    [lineLimiterMaxKeys]skipSlot
	overflow atomic.Int64
	writers  atomic.Int64
	// since is when the first line was counted, as sinceStamp encodes it; zero
	// means nothing is counted.
	since atomic.Int64
}

// skipSlot is one key's count. key is nil until the slot is claimed.
type skipSlot struct {
	key atomic.Pointer[[2]string]
	n   atomic.Int64
}

// skipSeed seeds the hash a key's first probe slot is taken from.
var skipSeed = maphash.MakeSeed()

// count counts one line under (a, b). It allocates only when it claims a slot
// for a key the table does not hold yet: at most lineLimiterMaxKeys times a
// table.
func (t *skipTable) count(a, b string) {
	h := maphash.String(skipSeed, a) ^ bits.RotateLeft64(maphash.String(skipSeed, b), 1)
	start := int(h % lineLimiterMaxKeys)
	var mine *[2]string
	for i := range lineLimiterMaxKeys {
		s := &t.slots[(start+i)%lineLimiterMaxKeys]
		k := s.key.Load()
		if k == nil {
			if mine == nil {
				mine = &[2]string{a, b}
			}
			if s.key.CompareAndSwap(nil, mine) {
				k = mine
			} else {
				k = s.key.Load()
			}
		}
		if k[0] == a && k[1] == b {
			s.n.Add(1)
			return
		}
	}
	t.overflow.Add(1)
}

// sinceStamp encodes now as a skipTable's since: the time after epoch (on the
// monotonic clock when now carries it), plus one so that zero stays "none".
func sinceStamp(now time.Time) int64 {
	return int64(max(now.Sub(epoch), 0)) + 1
}

// sinceTime decodes a skipTable's since.
func sinceTime(stamp int64) time.Time { return epoch.Add(time.Duration(stamp - 1)) }

// drained returns t once no Skip is counting in it any more. t has been
// swapped out, so a Skip arriving now counts in its successor; the wait is
// for the few already inside, which hold no lock and finish in nanoseconds.
func (t *skipTable) drained() *skipTable {
	for t.writers.Load() != 0 {
		runtime.Gosched()
	}
	return t
}

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
	l.counts.Store(new(skipTable))
	return l
}

// pending reports whether any line is counted and not yet reported. Two
// atomic loads: an Allow with nothing pending pays only these.
func (l *LineLimiter) pending() bool { return l.counts.Load().since.Load() != 0 }

// registered are the limiters ReportDue and FlushReports cover: the
// package-level ones, a handful, registered once at start-up.
var registered struct {
	mu       sync.Mutex
	limiters []*LineLimiter
}

// Register adds l to the limiters ReportDue and FlushReports cover, and
// returns it.
func Register(l *LineLimiter) *LineLimiter {
	registered.mu.Lock()
	defer registered.mu.Unlock()
	registered.limiters = append(registered.limiters, l)
	return l
}

// registeredLimiters is a copy of the registered limiters.
func registeredLimiters() []*LineLimiter {
	registered.mu.Lock()
	defer registered.mu.Unlock()
	return append([]*LineLimiter(nil), registered.limiters...)
}

// ReportDue writes the report of every registered limiter whose interval has
// passed by now.
func ReportDue(now time.Time) {
	for _, l := range registeredLimiters() {
		if l.pending() {
			l.reportDue(now)
		}
	}
}

// FlushReports writes every registered limiter's report now, whatever its
// interval: at shutdown, so what was counted is not lost with the process.
func FlushReports() {
	for _, l := range registeredLimiters() {
		if l.pending() {
			l.Flush()
		}
	}
}

// Allow reports whether a line may be written at now. A caller told no must
// call Skip, which counts the line for the next report.
func (l *LineLimiter) Allow(now time.Time) bool {
	if l.pending() {
		l.reportDue(now)
	}
	return l.budget.Allow(now)
}

// Skip counts a line that was not written under the key (a, b). It takes no
// lock, and allocates only to add a key to the table.
func (l *LineLimiter) Skip(now time.Time, a, b string) {
	t := l.enter()
	if t.since.Load() == 0 {
		t.since.CompareAndSwap(0, sinceStamp(now))
	}
	t.count(a, b)
	t.writers.Add(-1)
}

// enter returns the table lines are counted in now, with the caller counted
// among its writers. Checking the table is still current after joining it is
// what lets a report wait for exactly the writers that can still touch it: one
// that joined a table already swapped out leaves it and joins its successor.
func (l *LineLimiter) enter() *skipTable {
	for {
		t := l.counts.Load()
		t.writers.Add(1)
		if l.counts.Load() == t {
			return t
		}
		t.writers.Add(-1)
	}
}

// reportDue writes the report when the interval since the first line it
// counts has passed. Of callers racing to it, the one whose swap succeeds
// reports; the rest return.
func (l *LineLimiter) reportDue(now time.Time) {
	t := l.counts.Load()
	stamp := t.since.Load()
	if stamp == 0 || now.Sub(sinceTime(stamp)) < l.every {
		return
	}
	if l.counts.CompareAndSwap(t, new(skipTable)) {
		l.write(t.drained())
	}
}

// Flush writes the report now, whatever the interval. For shutdown and tests.
func (l *LineLimiter) Flush() {
	l.write(l.counts.Swap(new(skipTable)).drained())
}

// write logs one line per key counted in t, and one for the overflow.
func (l *LineLimiter) write(t *skipTable) {
	stamp := t.since.Load()
	if stamp == 0 {
		return
	}
	since := sinceTime(stamp)
	for i := range t.slots {
		s := &t.slots[i]
		if k := s.key.Load(); k != nil && s.n.Load() > 0 {
			l.log(l.labels[0], k[0], l.labels[1], k[1],
				"not_written", s.n.Load(), "since", since, "max_per_second", l.budget.Max())
		}
	}
	if n := t.overflow.Load(); n > 0 {
		l.log(l.labels[0], "(other)", l.labels[1], "(other)",
			"not_written", n, "since", since, "max_per_second", l.budget.Max())
	}
}

// log writes the report line at the limiter's level.
func (l *LineLimiter) log(args ...any) {
	switch {
	case l.level >= slog.LevelError:
		L.LogError(l.summary, args...)
	case l.level >= slog.LevelWarn:
		L.LogWarn(l.summary, args...)
	case l.level >= slog.LevelInfo:
		L.LogInfo(l.summary, args...)
	default:
		L.LogDebug(l.summary, args...)
	}
}
