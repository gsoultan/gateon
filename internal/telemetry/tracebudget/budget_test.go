// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracebudget

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/gsoultan/gateon/internal/config"
	dto "github.com/prometheus/client_model/go"
)

func TestMaxBytesIsTheProfileUnlessTheEnvironmentSaysOtherwise(t *testing.T) {
	td := config.DefaultsFor(config.TierStandard)
	for env, want := range map[string]int64{
		"":        td.TraceStoreMaxBytes,
		"512":     512 << 20,
		"0":       td.TraceStoreMaxBytes, // not positive: ignored
		"lots":    td.TraceStoreMaxBytes, // malformed: ignored
		" 64 ":    64 << 20,
		"-1":      td.TraceStoreMaxBytes,
		"1048576": 1 << 40,
	} {
		t.Setenv(EnvMaxMB, env)
		if got := MaxBytes(td); got != want {
			t.Errorf("%s=%q: MaxBytes = %d, want %d", EnvMaxMB, env, got, want)
		}
	}
}

// TestEveryProfileBoundsTheTraceStore: a profile with no budget is a trace
// store bounded by age alone, which is what filled the disk.
func TestEveryProfileBoundsTheTraceStore(t *testing.T) {
	for _, tier := range []config.Tier{config.TierMinimal, config.TierStandard, config.TierEnterprise} {
		if b := config.DefaultsFor(tier).TraceStoreMaxBytes; b <= 0 {
			t.Errorf("profile %s has no trace store budget (%d)", tier, b)
		}
	}
}

func TestFloor(t *testing.T) {
	const mem = 4 << 20
	for _, c := range []struct {
		total uint64
		want  uint64
	}{
		{48 << 20, 16 << 20},  // a tiny disk: four memtables, not a twentieth
		{10 << 30, 512 << 20}, // a twentieth
		{1 << 40, maxFloor},   // capped
		{0, 4 * uint64(mem)},  // unknown size: still the memtables
	} {
		if got := Floor(c.total, mem); got != c.want {
			t.Errorf("Floor(%d MiB) = %d MiB, want %d MiB", c.total>>20, got>>20, c.want>>20)
		}
	}
}

// TestFindCutoffEvictsOnlyWhatIsNeeded: the cutoff is the earliest time with
// enough bytes below it, so the newest traces stay.
func TestFindCutoffEvictsOnlyWhatIsNeeded(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(100 * time.Minute)
	// One byte per second of traces.
	below := func(at time.Time) uint64 { return uint64(max(at.Sub(start)/time.Second, 0)) }

	got := FindCutoff(start, end, 600, below)
	if want := start.Add(10 * time.Minute); got.Sub(want).Abs() > time.Second {
		t.Errorf("FindCutoff for 600 bytes = %v, want about %v", got, want)
	}
	if got := FindCutoff(start, end, 1<<40, below); !got.Equal(end) {
		t.Errorf("FindCutoff for more than everything = %v, want the newest moment %v", got, end)
	}
}

// fakeDisk is a filesystem whose free space a test sets.
type fakeDisk struct {
	total, avail uint64
	err          error
}

func (d *fakeDisk) usage(string) (vfs.DiskUsage, error) {
	return vfs.DiskUsage{TotalBytes: d.total, AvailBytes: d.avail, UsedBytes: d.total - d.avail}, d.err
}

// newTestGuard is a guard over disk with a clock the test moves.
func newTestGuard(disk *fakeDisk) (*Guard, *time.Time) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	g := NewGuard("/data/telemetry_pebble", 4<<20)
	g.usage = disk.usage
	g.now = func() time.Time { return now }
	return g, &now
}

func droppedDiskFull(t *testing.T) float64 {
	t.Helper()
	var m dto.Metric
	if err := dropped.WithLabelValues("disk_full").Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// TestANearlyFullDiskStopsTraceWritesUntilSpaceComesBack: on a full disk the
// store kept writing until Pebble failed, then retried for ever. Below the
// floor it stops, counts what it drops, says why, and resumes only once the
// free space is half as much again above the floor.
func TestANearlyFullDiskStopsTraceWritesUntilSpaceComesBack(t *testing.T) {
	disk := &fakeDisk{total: 10 << 30, avail: 5 << 30}
	g, now := newTestGuard(disk)
	if !g.Admit(10) || g.Paused() != "" {
		t.Fatal("a guard with half the disk free refused a batch")
	}

	disk.avail = 100 << 20 // under the 512 MiB floor
	*now = now.Add(checkEvery)
	before := droppedDiskFull(t)
	if g.Admit(10) {
		t.Fatal("a batch was admitted with 100 MiB free under a 512 MiB floor")
	}
	if got := droppedDiskFull(t) - before; got != 10 {
		t.Errorf("gateon_trace_dropped_total{disk_full} rose by %v, want 10", got)
	}
	if r := g.Paused(); !strings.Contains(r, "disk nearly full") {
		t.Errorf("Paused() = %q, want it to say the disk is nearly full", r)
	}

	disk.avail = 600 << 20 // above the floor, not above the hysteresis
	*now = now.Add(checkEvery)
	if g.Admit(1) {
		t.Error("writes resumed at 600 MiB free, inside the hysteresis over a 512 MiB floor")
	}
	disk.avail = 800 << 20
	*now = now.Add(checkEvery)
	if !g.Admit(1) || g.Paused() != "" {
		t.Errorf("writes did not resume at 800 MiB free (Paused %q)", g.Paused())
	}
}

// TestTheFreeSpaceIsReadAtMostOnceACheckPeriod: Admit runs every flush.
func TestTheFreeSpaceIsReadAtMostOnceACheckPeriod(t *testing.T) {
	disk := &fakeDisk{total: 10 << 30, avail: 5 << 30}
	g, now := newTestGuard(disk)
	reads := 0
	g.usage = func(d string) (vfs.DiskUsage, error) { reads++; return disk.usage(d) }
	for range 10 {
		g.Admit(1)
	}
	*now = now.Add(checkEvery)
	g.Admit(1)
	if reads != 2 {
		t.Errorf("the free space was read %d times over one period and a check, want 2", reads)
	}
}

// TestADiskFullErrorPausesAndBacksOff: Pebble's background error for a full
// disk pauses writes and starts a backoff that doubles to its ceiling.
func TestADiskFullErrorPausesAndBacksOff(t *testing.T) {
	disk := &fakeDisk{total: 10 << 30, avail: 0}
	g, now := newTestGuard(disk)
	enospc := fmt.Errorf("write 000123.sst: %w", syscall.ENOSPC)
	g.BackgroundError(enospc)
	if r := g.Paused(); !strings.Contains(r, "no space left") {
		t.Errorf("Paused() = %q after ENOSPC, want it to say there is no space left", r)
	}
	if d := g.backoffUntil.Sub(*now); d != minBackoff {
		t.Errorf("first backoff = %v, want %v", d, minBackoff)
	}
	for range 10 {
		g.BackgroundError(enospc)
	}
	if d := g.backoffUntil.Sub(*now); d != maxBackoff {
		t.Errorf("backoff after many failures = %v, want the ceiling %v", d, maxBackoff)
	}

	g.BackgroundError(errors.New("pebble: corruption in 000124.sst"))
	if g.backoffUntil.Sub(*now) != maxBackoff {
		t.Error("an error that is not disk-full changed the backoff")
	}
}

// failingFS fails every Create with ENOSPC and counts them.
type failingFS struct {
	vfs.FS
	creates int
}

func (f *failingFS) Create(string) (vfs.File, error) {
	f.creates++
	return nil, &pebbleWriteError{syscall.ENOSPC}
}

type pebbleWriteError struct{ errno syscall.Errno }

func (e *pebbleWriteError) Error() string { return "create: " + e.errno.Error() }
func (e *pebbleWriteError) Unwrap() error { return e.errno }

// TestFileCreationWaitsOutTheBackoff: a creation on a full disk starts the
// backoff, and the next one waits for it -- which is what turns Pebble's
// immediate compaction retry from a loop into one attempt per period. Close
// releases a waiting creation so shutdown does not wait the backoff out.
func TestFileCreationWaitsOutTheBackoff(t *testing.T) {
	disk := &fakeDisk{total: 10 << 30, avail: 0}
	g := NewGuard("/data/telemetry_pebble", 4<<20)
	g.usage = disk.usage
	inner := &failingFS{FS: vfs.NewMem()}
	fs := backoffFS{FS: inner, g: g}

	if _, err := fs.Create("000001.sst"); !isNoSpace(err) {
		t.Fatalf("Create = %v, want ENOSPC", err)
	}
	if g.Paused() == "" {
		t.Fatal("ENOSPC from a creation did not pause writes")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = fs.Create("000002.sst")
	}()
	select {
	case <-done:
		t.Fatal("a creation right after ENOSPC did not wait for the backoff")
	case <-time.After(minBackoff / 4):
	}
	g.Close()
	<-done
	if inner.creates != 2 {
		t.Errorf("creates = %d, want 2", inner.creates)
	}
}

// TestConfigureRoutesPebbleThroughTheGuard: the options a store opens with
// carry the guard's filesystem, its listener and a logger that is not
// Pebble's default.
func TestConfigureRoutesPebbleThroughTheGuard(t *testing.T) {
	g := NewGuard(t.TempDir(), 1<<20)
	opts := &pebble.Options{}
	g.Configure(opts)
	opts.EnsureDefaults()
	if _, ok := opts.FS.(backoffFS); !ok {
		t.Errorf("FS = %T, want the guard's backoffFS", opts.FS)
	}
	if _, ok := opts.Logger.(pebbleLogger); !ok {
		t.Errorf("Logger = %T, want the gateway's", opts.Logger)
	}
	opts.EventListener.BackgroundError(fmt.Errorf("x: %w", syscall.ENOSPC))
	if g.Paused() == "" {
		t.Error("a background error through the configured listener did not reach the guard")
	}
	g.Close()
}

// TestANilGuardAdmitsEverything: a store opened without one behaves as before.
func TestANilGuardAdmitsEverything(t *testing.T) {
	var g *Guard
	g.Check()
	g.BackgroundError(syscall.ENOSPC)
	g.Close()
	if !g.Admit(1) || g.Paused() != "" {
		t.Error("a nil guard refused a batch")
	}
}

// TestAFullDiskUnderTheCommitStopsTheStoreInsteadOfTheProcess: on a disk
// filled to the last byte, Pebble's write-ahead-log write failed and its
// logger's Fatalf ended the process -- "pebble: fatal commit error: write
// 000014.log: no space left on device", logged at INFO, and the proxy went
// down with the trace store. A full disk now stops the store for the life of
// the process; it does not resume when space comes back, because Pebble's
// commit pipeline cannot be trusted after the failure.
func TestAFullDiskUnderTheCommitStopsTheStoreInsteadOfTheProcess(t *testing.T) {
	disk := &fakeDisk{total: 10 << 30, avail: 5 << 30}
	g, now := newTestGuard(disk)
	l := pebbleLogger{g: g}

	l.Fatalf("pebble: fatal commit error: %v", fmt.Errorf("write 000014.log: %w", syscall.ENOSPC))

	if g.Writable() || g.Admit(1) {
		t.Fatal("the store still writes after its commit pipeline failed on a full disk")
	}
	if r := g.Paused(); !strings.Contains(r, "stopped") {
		t.Errorf("Paused() = %q, want it to say the store stopped", r)
	}
	*now = now.Add(time.Hour)
	if g.Admit(1) {
		t.Error("a stopped store resumed when space came back; only a restart may")
	}
}
