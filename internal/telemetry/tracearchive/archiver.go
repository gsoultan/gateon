// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"context"
	"errors"
	"io/fs"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// tickInterval is how often the archiver looks for work. An hour closes
	// once an hour; the minute is for retrying soon after a failure and for
	// spreading a backlog out.
	tickInterval = time.Minute
	// settleDelay is how long after an hour closes the archiver waits to write
	// it, so the traces still queued for the store, which flushes every few
	// seconds, are in it first.
	settleDelay = 2 * time.Minute
	// exportBudget and verifyBudget cap the hours one tick writes or checks.
	// The first run over days of history, or a cut in retention that brings
	// days of hours up for pruning at once, is then a few minutes of background
	// work on the 2-core hosts Gateon is sized for, not a core for as long as
	// it takes. Hours with no traces are skipped and do not count.
	exportBudget = 6
	verifyBudget = 6
	// verifyLookahead is how far ahead of the store's retention cutoff the
	// archiver checks hours, so each is known complete before the hourly prune
	// that deletes it comes round.
	verifyLookahead = 2 * time.Hour
	// pruneHoldLimit is how long past its retention the store is made to keep
	// an hour the archive has not caught up with. Holding it for good because
	// archiving is failing would fill the disk that is most likely why.
	pruneHoldLimit = 24 * time.Hour
	// retentionEvery is how often the archive's own retention runs.
	retentionEvery = time.Hour
)

var (
	segmentsWritten = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gateon_trace_archive_segments_written_total",
		Help: "Hourly trace archive files written, including rewrites that merged in late traces.",
	})
	tracesWritten = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gateon_trace_archive_traces_written_total",
		Help: "Traces written to trace archive files.",
	})
	archiveBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_trace_archive_bytes",
		Help: "Disk used by the trace archive, as of its last scan.",
	})
	archiveErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateon_trace_archive_errors_total",
		Help: "Trace archive failures, by stage: export, verify or retention.",
	}, []string{"stage"})
	unverifiedPrunes = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gateon_trace_archive_unverified_prunes_total",
		Help: "Prunes the trace store made past hours the archive could not confirm, after holding them as long as it may.",
	})
)

// Archiver copies closed hours out of the trace store, reconciles them again
// before the store deletes them, and keeps the archive within its retention
// and size budget. One goroutine, Run, does all of the writing.
type Archiver struct {
	// next is the first hour the export has not reached; zero until the
	// first tick works it out. Only Run's goroutine touches it, and lastRetention.
	next          Segment
	lastRetention time.Time
	tickFailed    bool
	// verifiedThrough is the time, in Unix nanoseconds, before which every
	// trace the store holds is also in the archive, as of the last check. It is
	// how far the prune guard lets the store delete.
	verifiedThrough atomic.Int64
	state           atomic.Pointer[runState]
}

// runState is what Status reports. It is replaced, never modified.
type runState struct {
	stats       catalogStats
	lastWritten time.Time
	lastErr     string
	lastErrAt   time.Time
}

var std = &Archiver{}

// Default returns the process's archiver.
func Default() *Archiver { return std }

// Run archives until ctx ends. It first installs the archiver as the trace
// store's prune guard, and leaves it installed after returning: a store that
// prunes once the archiver has stopped is then held at the last hour the
// archive confirmed, which is the answer that loses nothing.
func (a *Archiver) Run(ctx context.Context) {
	telemetry.SetTracePruneGuard(a.guard)
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		a.ArchiveNow(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// ArchiveNow makes one pass -- the archive's retention when it is due, then,
// if archiving is on, the hours that have closed and the hours the store will
// prune next -- and returns when it is done. Run makes one every minute. An
// Archiver's zero value is ready to use; only one goroutine may call this at a
// time.
func (a *Archiver) ArchiveNow(ctx context.Context) { a.tick(ctx, time.Now()) }

func (a *Archiver) tick(ctx context.Context, now time.Time) {
	s := CurrentSettings()
	a.tickFailed = false
	if now.Sub(a.lastRetention) >= retentionEvery {
		a.lastRetention = now
		a.retain(s, now)
	}
	if s.Enabled {
		a.exportClosed(ctx, s, now)
		a.verifyAhead(ctx, s, now)
	}
	// A problem is reported until a tick gets through without one, so the
	// dashboard stops showing an error once whatever caused it is fixed.
	if !a.tickFailed && a.snapshot().lastErr != "" {
		a.update(func(st *runState) { st.lastErr, st.lastErrAt = "", time.Time{} })
	}
}

// exportClosed archives the hours that have closed since the last one it
// reached, oldest first.
func (a *Archiver) exportClosed(ctx context.Context, s Settings, now time.Time) {
	seg, ok, err := a.resume(ctx, s, now)
	for n := 0; err == nil && ok && n < exportBudget; n++ {
		if seg.End().Add(settleDelay).After(now) {
			return
		}
		if err = a.archiveHour(ctx, s, seg, now); err != nil {
			break
		}
		a.next = seg.Next()
		seg, ok, err = nextStored(ctx, a.next)
	}
	if err != nil {
		a.fail("export", err)
	}
}

// archiveHour reconciles one hour and, if that wrote a file, applies the
// archive's retention straight away. The size budget is a promise about the
// disk: checked only on the hourly pass, a first run over a week of history
// wrote the whole week -- several times the budget -- before anything was
// removed.
func (a *Archiver) archiveHour(ctx context.Context, s Settings, seg Segment, now time.Time) error {
	written, err := a.reconcile(ctx, s, seg)
	if err != nil || !written {
		return err
	}
	a.update(func(st *runState) { st.lastWritten = time.Now() })
	a.retain(s, now)
	return nil
}

// resume returns the first hour with traces the export should consider: the
// one after the newest archived hour, or the store's oldest on a first run,
// and never one the archive's retention would delete as soon as it was written.
func (a *Archiver) resume(ctx context.Context, s Settings, now time.Time) (Segment, bool, error) {
	if a.next.start.IsZero() {
		if st := a.snapshot().stats; st.segments > 0 {
			a.next = st.newest.Next()
		}
	}
	from := a.next
	if floor := retentionFloor(s, now); from.start.Before(floor.start) {
		from = floor
	}
	return nextStored(ctx, from)
}

// retentionFloor is the oldest hour the archive's retention keeps.
func retentionFloor(s Settings, now time.Time) Segment {
	return SegmentAt(now.AddDate(0, 0, -max(s.RetentionDays, 1)))
}

// verifyAhead reconciles the hours the store will prune next, so that by the
// time a prune reaches an hour the archive holds all of it -- including the
// traces that reached the store after the hour was first archived. Each hour
// is checked once, as it comes within verifyLookahead of the cutoff.
func (a *Archiver) verifyAhead(ctx context.Context, s Settings, now time.Time) {
	cutoff := telemetry.TracePruneCutoff(now)
	if cutoff.IsZero() {
		return // the store keeps everything, so there is nothing to get ahead of
	}
	horizon := SegmentAt(cutoff.Add(verifyLookahead))
	seg, ok, err := a.firstToVerify(ctx, s, now)
	for n := 0; err == nil && ok && seg.start.Before(horizon.start); n++ {
		if n == verifyBudget {
			return
		}
		if err = a.archiveHour(ctx, s, seg, now); err != nil {
			break
		}
		a.verifiedThrough.Store(seg.End().UnixNano())
		seg, ok, err = nextStored(ctx, seg.Next())
	}
	if err != nil {
		// Not past the hour that failed: the guard holds the store there.
		a.fail("verify", err)
		return
	}
	a.verifiedThrough.Store(horizon.start.UnixNano())
}

// firstToVerify returns the first stored hour not yet verified. Hours the
// archive's retention would not keep are passed over. So are hours older than
// the oldest one archived, once the archive is near its size budget: the
// budget let them go, and writing them again only for it to delete them again
// would be work in a loop. Below the budget they are written -- retention may
// have been raised, and the store still has them.
func (a *Archiver) firstToVerify(ctx context.Context, s Settings, now time.Time) (Segment, bool, error) {
	from := SegmentAt(time.Unix(0, a.verifiedThrough.Load()))
	if floor := retentionFloor(s, now); from.start.Before(floor.start) {
		from = floor
	}
	st := a.snapshot().stats
	if st.segments > 0 && st.oldest.start.After(from.start) && !roomToBackfill(s, st) {
		from = st.oldest
	}
	return nextStored(ctx, from)
}

// roomToBackfill reports whether the archive has room for hours older than
// any it holds. The tenth held back is so that an hour the budget pushed out
// is not the one that fits again the moment it has gone.
func roomToBackfill(s Settings, st catalogStats) bool {
	return s.MaxBytes <= 0 || st.bytes < s.MaxBytes/10*9
}

// guard answers the trace store before it prunes: whole hours only, and none
// the archive has not confirmed -- for up to pruneHoldLimit past retention.
// Past that the store gets its way, and the metric and the log say so.
func (a *Archiver) guard(cutoff time.Time) time.Time {
	if !CurrentSettings().Enabled {
		return cutoff
	}
	limit := SegmentAt(cutoff).start
	verified := time.Unix(0, a.verifiedThrough.Load()).UTC()
	if !verified.Before(limit) {
		return limit
	}
	floor := SegmentAt(cutoff.Add(-pruneHoldLimit)).start
	if !verified.Before(floor) {
		return verified
	}
	unverifiedPrunes.Inc()
	logger.Default().LogError("trace archive: the archive has not caught up, so the trace store is "+
		"deleting hours it cannot confirm were archived", "deleting_before", floor, "verified_through", verified)
	return floor
}

// nextStored returns the hour of the first stored trace at or after from. A
// store that is not open has nothing stored; one that fails to read is an
// error, not an empty store -- read as empty, it would mark every hour up to
// the horizon verified and let the prune take them unchecked.
func nextStored(ctx context.Context, from Segment) (Segment, bool, error) {
	var at time.Time
	found := false
	err := telemetry.ScanTraces(ctx, telemetry.TraceScan{From: from.start}, func(key, _ []byte) bool {
		at, found = telemetry.TraceKeyTime(key), true
		return false
	})
	if errors.Is(err, telemetry.ErrTraceStoreClosed) {
		return Segment{}, false, nil
	}
	return SegmentAt(at), found, err
}

// retain applies the archive's retention and refreshes what Status reports.
func (a *Archiver) retain(s Settings, now time.Time) {
	stats, err := enforceRetention(s, now)
	if err != nil {
		a.fail("retention", err)
	}
	a.update(func(st *runState) { st.stats = stats })
	archiveBytes.Set(float64(stats.bytes))
}

func (a *Archiver) fail(stage string, err error) {
	a.tickFailed = true
	archiveErrors.WithLabelValues(stage).Inc()
	logger.Default().LogError("trace archive: a stage failed", "stage", stage, "error", err)
	a.update(func(st *runState) { st.lastErr, st.lastErrAt = describe(err), time.Now() })
}

// describe says what went wrong in words for the dashboard. The error itself
// names paths on the gateway's disk; it goes to the log, not to a page that
// also renders traffic from strangers.
func describe(err error) string {
	switch {
	case errors.Is(err, syscall.ENOSPC):
		return "The disk holding the trace archive is full."
	case errors.Is(err, fs.ErrPermission):
		return "Gateon is not allowed to write to the trace archive directory."
	case errors.Is(err, telemetry.ErrTraceStoreClosed):
		return "The trace store is not open, so there is nothing to archive."
	default:
		return "Archiving traces failed; the gateway log has the details."
	}
}

func (a *Archiver) snapshot() runState {
	if st := a.state.Load(); st != nil {
		return *st
	}
	return runState{}
}

// update replaces the run state with a modified copy. Only Run's goroutine
// calls it, so there is no lost update to guard against.
func (a *Archiver) update(change func(*runState)) {
	st := a.snapshot()
	change(&st)
	a.state.Store(&st)
}
