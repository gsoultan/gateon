// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracebudget

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/pebble/vfs"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// dropped counts the traces the store did not write. The one label value is a
// constant here, never request data.
var dropped = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateon_trace_dropped_total",
	Help: "Traces the trace store did not write, by reason (disk_full: the disk holding it is nearly full).",
}, []string{"reason"})

// storeBytes is the trace store's disk use at the last check, and storeMax its
// budget, so an alert can watch one approach the other.
var (
	storeBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_trace_store_bytes",
		Help: "Disk the live trace store uses, at the last check.",
	})
	storeMax = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_trace_store_max_bytes",
		Help: "The most disk the live trace store may use before its oldest traces are evicted.",
	})
)

// ReportUsage publishes the store's disk use and its budget.
func ReportUsage(used uint64, budget int64) {
	storeBytes.Set(float64(used))
	storeMax.Set(float64(budget))
}

const (
	// checkEvery is how often the free space is read: a statfs, cheap, but
	// not something a flush every second needs to repeat.
	checkEvery = 5 * time.Second
	// nearFloorCheckEvery is the period once free space is within twice the
	// floor.
	nearFloorCheckEvery = time.Second
	// logEvery bounds the ERROR lines a paused store writes: one a minute,
	// saying how many traces it dropped, rather than one per flush.
	logEvery = time.Minute
	// The backoff on file creation after the disk reported it full: from
	// minBackoff, doubling on each further failure, up to maxBackoff.
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

// Guard decides whether the trace store may write, from the free space on its
// disk and from the disk-full errors Pebble reports. It is used off the
// request path only: by the store's own goroutine and Pebble's.
type Guard struct {
	dir      string
	memtable int64
	// usage reads the filesystem holding dir; now is the clock. Both are
	// replaced by a test.
	usage func(dir string) (vfs.DiskUsage, error)
	now   func() time.Time

	mu           sync.Mutex
	nextCheck    time.Time
	backoff      time.Duration
	backoffUntil time.Time
	lastLog      time.Time
	unlogged     uint64

	// paused is the reason writes are stopped, nil while they are not. Read
	// by /readyz without the lock.
	paused atomic.Pointer[string]
	// stopped is set once Pebble's commit pipeline failed on a full disk:
	// nothing more is written until a restart, whatever the free space.
	stopped  atomic.Bool
	closing  chan struct{}
	closeOne sync.Once
}

// NewGuard guards a trace store in dir whose memtables are memtable bytes.
func NewGuard(dir string, memtable int64) *Guard {
	return &Guard{
		dir: dir, memtable: memtable,
		usage:   vfs.Default.GetDiskUsage,
		now:     time.Now,
		closing: make(chan struct{}),
	}
}

// Paused is why trace writes are stopped, and "" while they are not.
func (g *Guard) Paused() string {
	if g == nil {
		return ""
	}
	if r := g.paused.Load(); r != nil {
		return *r
	}
	return ""
}

// Check reads the free space when it is due, and pauses or resumes writes.
func (g *Guard) Check() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.checkLocked(g.now())
}

// Admit reports whether a batch of n traces may be written, reading the free
// space first when it is due. A refused batch is counted, and the count is
// logged at ERROR at most once a minute.
func (g *Guard) Admit(n int) bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.checkLocked(now)
	if g.paused.Load() == nil && !g.stopped.Load() {
		return true
	}
	dropped.WithLabelValues("disk_full").Add(float64(n))
	g.unlogged += uint64(n)
	if now.Sub(g.lastLog) >= logEvery {
		logger.L.LogError("trace store: traces dropped because the disk is nearly full; the data plane is "+
			"unaffected, and traces resume once space is freed", "dropped", g.unlogged, "reason", g.Paused())
		g.lastLog, g.unlogged = now, 0
	}
	return false
}

// checkLocked pauses writes when free space is below the floor, and resumes
// them once it is half as much again above it, so a store at the edge does
// not flap.
func (g *Guard) checkLocked(now time.Time) {
	if now.Before(g.nextCheck) {
		return
	}
	g.nextCheck = now.Add(checkEvery)
	du, err := g.usage(g.dir)
	if err != nil {
		return
	}
	floor := Floor(du.TotalBytes, g.memtable)
	if du.AvailBytes < 2*floor {
		// Close to the floor, look every second: at a few thousand requests
		// a second the store writes megabytes between five-second checks.
		g.nextCheck = now.Add(nearFloorCheckEvery)
	}
	switch {
	case g.paused.Load() == nil && du.AvailBytes < floor:
		g.pauseLocked(fmt.Sprintf("trace store paused: disk nearly full (%d MiB free, keeps %d MiB free)",
			du.AvailBytes>>20, floor>>20))
	case g.paused.Load() != nil && !g.stopped.Load() && du.AvailBytes >= floor+floor/2:
		g.paused.Store(nil)
		g.backoff, g.backoffUntil = 0, time.Time{}
		logger.L.LogInfo("trace store: disk space is back; writing traces again",
			"free_mib", du.AvailBytes>>20, "dropped_unlogged", g.unlogged)
		g.unlogged = 0
	}
}

// pauseLocked stops writes for reason, logging the change at ERROR.
func (g *Guard) pauseLocked(reason string) {
	if g.paused.Swap(&reason) == nil {
		logger.L.LogError("trace store: stopped writing traces; /readyz reports not ready until space is freed",
			"reason", reason, "dir", g.dir)
		g.lastLog = g.now()
	}
}

// Writable reports whether the store may be written at all: false once it has
// stopped for good. Pruning checks it; a paused store may still delete.
func (g *Guard) Writable() bool {
	return g == nil || !g.stopped.Load()
}

// stop ends trace writes for the life of the process, for reason.
func (g *Guard) stop(reason, detail string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stopped.Store(true)
	g.paused.Store(&reason)
	logger.L.LogError("trace store: stopped writing for the life of this process; the data plane is unaffected",
		"reason", reason, "error", detail, "dir", g.dir)
	g.lastLog = g.now()
}

// BackgroundError is Pebble's background-error event. A disk-full error
// pauses writes and starts the creation backoff; any other is logged at ERROR,
// at most once a minute, where Pebble's default logged every one at INFO.
func (g *Guard) BackgroundError(err error) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if isNoSpace(err) {
		g.pauseLocked("trace store paused: no space left on the disk holding it")
		g.backoff = min(max(g.backoff*2, minBackoff), maxBackoff)
		g.backoffUntil = now.Add(g.backoff)
		g.nextCheck = time.Time{}
		return
	}
	if now.Sub(g.lastLog) >= logEvery {
		logger.L.LogError("trace store: background error", "error", err)
		g.lastLog = now
	}
}

// DiskSlow is Pebble's slow-disk event, logged at WARN once a minute at most.
//
// Not while writes are paused: a creation held in the disk-full backoff is
// slow on purpose, and Pebble's health check cannot tell the difference.
func (g *Guard) DiskSlow(info vfs.DiskSlowInfo) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paused.Load() != nil {
		return
	}
	if now := g.now(); now.Sub(g.lastLog) >= logEvery {
		logger.L.LogWarn("trace store: disk slow", "path", info.Path, "duration", info.Duration)
		g.lastLog = now
	}
}

// wait holds a file creation until the backoff after a disk-full error has
// passed, or the guard is closed.
func (g *Guard) wait() {
	g.mu.Lock()
	d := g.backoffUntil.Sub(g.now())
	g.mu.Unlock()
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-g.closing:
	}
}

// Close releases any creation held in backoff, so closing the store does not
// wait out the backoff. Call it before closing Pebble.
func (g *Guard) Close() {
	if g == nil {
		return
	}
	g.closeOne.Do(func() { close(g.closing) })
}
