// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// counter reads a counter through the collector rather than
// prometheus/testutil, which would pull a module into go.mod for the sake of
// an assertion.
func counter(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

// Nodes sharing a root each export their own hours. Another node's newer hour
// is not this node's progress: taken for it, this node would never export an
// hour of its own older than the other's newest. What Status reports, though,
// is the whole archive.
func TestArchiver_AnotherNodesHoursAreNotItsProgress(t *testing.T) {
	openStore(t)
	root := enableArchive(t)
	now := time.Now().UTC()
	mine, theirs := SegmentAt(now.Add(-3*time.Hour)), SegmentAt(now.Add(-2*time.Hour))
	writeNodeFile(t, root, "gw-other", theirs, testTrace{id: "other", at: theirs.Start().Add(time.Minute)})
	store(t, testTrace{id: "mine", at: mine.Start().Add(time.Minute)})

	a := &Archiver{}
	a.tick(context.Background(), now)
	if !exists(mine.path(root, testNode)) {
		t.Fatal("this node's hour was not archived: another node's newer hour was taken for this node's progress")
	}
	st := a.Status()
	if st.Segments != 2 || !slices.Equal(st.Nodes, []string{"gw-other", testNode}) ||
		!st.Oldest.Equal(mine.Start()) || !st.Newest.Equal(theirs.Start()) {
		t.Fatalf("status = %+v, want both nodes' hours", st)
	}
}

// Closed hours are archived, each in its own file; the hour still open is not.
func TestArchiver_WritesEachClosedHourOnce(t *testing.T) {
	openStore(t)
	root := enableArchive(t)
	now := time.Now().UTC()
	h1, h2, open := SegmentAt(now.Add(-3*time.Hour)), SegmentAt(now.Add(-2*time.Hour)), SegmentAt(now)
	store(t,
		testTrace{id: "a", at: h1.Start().Add(5 * time.Minute)},
		testTrace{id: "b", at: h1.Start().Add(50 * time.Minute)},
		testTrace{id: "c", at: h2.Start().Add(time.Minute)},
		testTrace{id: "d", at: now.Add(-time.Second)},
	)

	a := &Archiver{}
	a.tick(context.Background(), now)

	if got := ids(t, h1.path(root, testNode)); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("%s holds %v, want [a b]", h1.FileName(testNode), got)
	}
	if got := ids(t, h2.path(root, testNode)); !slices.Equal(got, []string{"c"}) {
		t.Fatalf("%s holds %v, want [c]", h2.FileName(testNode), got)
	}
	if exists(open.path(root, testNode)) {
		t.Fatal("the hour still open was archived")
	}

	// Nothing new, nothing written: the next tick must not rewrite what is done.
	before := counter(t, segmentsWritten)
	a.tick(context.Background(), now.Add(time.Minute))
	if after := counter(t, segmentsWritten); after != before {
		t.Fatalf("an idle tick wrote %v segment(s)", after-before)
	}
	if st := a.Status(); st.Segments != 2 || st.LastError != "" {
		t.Fatalf("status = %+v, want two segments and no error", st)
	}
}

// A trace is keyed by when its request started, so a long-lived connection
// reaches the store for an hour archived long before. The archiver checks each
// hour again as the store's cutoff approaches it, and merges the late trace in
// before the store may delete the hour.
func TestArchiver_MergesALateTraceBeforeTheStoreMayDeleteItsHour(t *testing.T) {
	openStore(t)
	root := enableArchive(t)
	now := time.Now().UTC()
	cutoff := telemetry.TracePruneCutoff(now)
	if cutoff.IsZero() {
		t.Fatal("the store keeps traces for good; the test needs a retention cutoff")
	}
	// Just beyond the lookahead now, inside it two hours from now.
	h := SegmentAt(cutoff.Add(verifyLookahead + time.Hour))
	store(t,
		testTrace{id: "early", at: h.Start().Add(10 * time.Minute)},
		testTrace{id: "later", at: h.Start().Add(40 * time.Minute)},
	)
	a := &Archiver{}
	a.tick(context.Background(), now)
	if got := ids(t, h.path(root, testNode)); !slices.Equal(got, []string{"early", "later"}) {
		t.Fatalf("first archive of the hour holds %v", got)
	}
	if limit := a.guard(cutoff); limit.After(cutoff) {
		t.Fatalf("guard let the store prune to %v, past its own cutoff %v", limit, cutoff)
	}

	store(t, testTrace{id: "late", at: h.Start().Add(20 * time.Minute)})
	a.tick(context.Background(), now.Add(2*time.Hour))

	if got := ids(t, h.path(root, testNode)); !slices.Equal(got, []string{"early", "late", "later"}) {
		t.Fatalf("after the check the hour holds %v, want the late trace merged in key order", got)
	}
	if v := time.Unix(0, a.verifiedThrough.Load()); !v.After(h.Start()) {
		t.Fatalf("verifiedThrough = %v, want past the hour it checked", v)
	}
}

// A merge keeps what the old file held that the store no longer does -- the
// store may have been emptied, or pruned while archiving was off.
func TestReconcile_KeepsWhatOnlyTheOldFileHeld(t *testing.T) {
	openStore(t)
	root := enableArchive(t)
	h := SegmentAt(time.Now().UTC().Add(-5 * time.Hour))
	writeFile(t, root, h,
		testTrace{id: "gone-1", at: h.Start().Add(time.Minute)},
		testTrace{id: "both", at: h.Start().Add(2 * time.Minute)},
		testTrace{id: "gone-2", at: h.Start().Add(4 * time.Minute)},
	)
	store(t,
		testTrace{id: "both", at: h.Start().Add(2 * time.Minute)},
		testTrace{id: "new", at: h.Start().Add(3 * time.Minute)},
	)

	a := &Archiver{}
	if _, err := a.reconcile(context.Background(), CurrentSettings(), h); err != nil {
		t.Fatal(err)
	}
	if got := ids(t, h.path(root, testNode)); !slices.Equal(got, []string{"gone-1", "both", "new", "gone-2"}) {
		t.Fatalf("merged hour holds %v", got)
	}
	// Now in step with the store: a second reconcile leaves it alone.
	written, err := a.reconcile(context.Background(), CurrentSettings(), h)
	if err != nil || written {
		t.Fatalf("second reconcile wrote=%v err=%v; want nothing to do", written, err)
	}
}

func TestGuard_HoldsUnconfirmedHoursForADayAtMost(t *testing.T) {
	enableArchive(t)
	cutoff := time.Date(2026, 9, 20, 10, 30, 0, 0, time.UTC)
	a := &Archiver{}

	a.verifiedThrough.Store(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC).UnixNano())
	if got, want := a.guard(cutoff), time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("all confirmed: guard = %v, want the cutoff's whole hour %v", got, want)
	}

	held := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	a.verifiedThrough.Store(held.UnixNano())
	if got := a.guard(cutoff); !got.Equal(held) {
		t.Fatalf("behind: guard = %v, want it held at %v", got, held)
	}

	before := counter(t, unverifiedPrunes)
	a.verifiedThrough.Store(0)
	if got, want := a.guard(cutoff), time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("far behind: guard = %v, want the hold limit %v", got, want)
	}
	if counter(t, unverifiedPrunes) != before+1 {
		t.Fatal("letting the store past unconfirmed hours was not counted")
	}
}

// With archiving off the store prunes exactly as it always has.
func TestGuard_WhenArchivingIsOffChangesNothing(t *testing.T) {
	enableArchive(t)
	t.Setenv(EnvEnabled, "false")
	cutoff := time.Date(2026, 9, 20, 10, 30, 15, 0, time.UTC)
	if got := (&Archiver{}).guard(cutoff); !got.Equal(cutoff) {
		t.Fatalf("guard = %v, want the cutoff untouched", got)
	}
}

func TestArchiver_WhenOffWritesNothing(t *testing.T) {
	openStore(t)
	root := enableArchive(t)
	t.Setenv(EnvEnabled, "false")
	now := time.Now().UTC()
	h := SegmentAt(now.Add(-3 * time.Hour))
	store(t, testTrace{id: "a", at: h.Start().Add(time.Minute)})

	(&Archiver{}).tick(context.Background(), now)

	if exists(h.path(root, testNode)) {
		t.Fatal("an hour was archived with archiving off")
	}
}

// A failure is reported in words a dashboard can show -- not an error string
// with the gateway's paths in it -- and cleared once a tick gets through.
func TestArchiver_ReportsAFailureUntilItClears(t *testing.T) {
	openStore(t)
	root := enableArchive(t)
	now := time.Now().UTC()
	h := SegmentAt(now.Add(-3 * time.Hour))
	store(t, testTrace{id: "a", at: h.Start().Add(time.Minute)})
	// A file where the node's directory must go.
	block := filepath.Join(root, testNode)
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	a := &Archiver{}
	a.tick(context.Background(), now)
	st := a.Status()
	if st.LastError == "" || strings.Contains(st.LastError, root) {
		t.Fatalf("LastError = %q; want a failure reported without the path", st.LastError)
	}

	if err := os.Remove(block); err != nil {
		t.Fatal(err)
	}
	a.tick(context.Background(), now.Add(time.Minute))
	if st := a.Status(); st.LastError != "" || !exists(h.path(root, testNode)) {
		t.Fatalf("after the fix: LastError = %q, archived = %v", st.LastError, exists(h.path(root, testNode)))
	}
}

// The size budget is a promise about the disk. Kept only by the hourly pass, a
// first run over days of history wrote all of them -- several times the budget
// -- before anything was removed.
func TestArchiver_KeepsTheSizeBudgetWhileCatchingUp(t *testing.T) {
	openStore(t)
	root := enableArchive(t)
	t.Setenv(EnvMaxMB, "1")
	now := time.Now().UTC()
	var backlog []testTrace
	rng := rand.New(rand.NewPCG(3, 4))
	for h := 48; h >= 2; h-- {
		hr := SegmentAt(now.Add(-time.Duration(h) * time.Hour))
		for i := range 50 {
			path := fmt.Sprintf("/%016x%016x%016x%016x", rng.Uint64(), rng.Uint64(), rng.Uint64(), rng.Uint64())
			backlog = append(backlog, testTrace{id: fmt.Sprintf("%d-%d", h, i), at: hr.Start().Add(time.Duration(i) * time.Second), path: strings.Repeat(path, 16)})
		}
	}
	store(t, backlog...)

	a := &Archiver{}
	for i := range 9 {
		a.tick(context.Background(), now.Add(time.Duration(i)*time.Minute))
		if size := treeSize(t, root); size > 1<<20 {
			t.Fatalf("after tick %d the archive holds %d bytes, over its 1 MiB budget", i+1, size)
		}
	}
	if st := a.Status(); st.Segments == 0 {
		t.Fatal("nothing was archived, so the budget was never tested")
	}
}

func treeSize(t *testing.T, root string) int64 {
	t.Helper()
	var n int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

// A file the archiver cannot open is not a damaged file. It may hold traces
// the store no longer has; replacing it with the store's copy would lose them.
func TestReconcile_LeavesAFileItCannotReadAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode")
	}
	openStore(t)
	root := enableArchive(t)
	h := SegmentAt(time.Now().UTC().Add(-5 * time.Hour))
	writeFile(t, root, h,
		testTrace{id: "a", at: h.Start().Add(time.Minute)},
		testTrace{id: "b", at: h.Start().Add(2 * time.Minute)},
	)
	store(t, testTrace{id: "d", at: h.Start().Add(30 * time.Minute)})
	if err := os.Chmod(h.path(root, testNode), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(h.path(root, testNode), 0o600) })

	if _, err := (&Archiver{}).reconcile(context.Background(), CurrentSettings(), h); err == nil {
		t.Fatal("reconcile reported success on a file it could not read")
	}
	_ = os.Chmod(h.path(root, testNode), 0o600)
	if got := ids(t, h.path(root, testNode)); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("the unreadable file was rewritten: it holds %v", got)
	}
}

// Raising the archive's retention reaches back for the hours the store still
// has. Passed over, they were released to the store's prune unarchived.
func TestArchiver_BackfillsWhenRetentionIsRaised(t *testing.T) {
	openStore(t)
	root := enableArchive(t)
	t.Setenv(EnvRetentionDays, "1")
	now := time.Now().UTC()
	old := SegmentAt(now.Add(-6 * 24 * time.Hour))
	store(t,
		testTrace{id: "old", at: old.Start().Add(10 * time.Minute)},
		testTrace{id: "new", at: now.Add(-8 * time.Hour)},
	)
	a := &Archiver{}
	a.tick(context.Background(), now)
	if exists(old.path(root, testNode)) {
		t.Fatal("an hour outside a one-day retention was archived")
	}

	t.Setenv(EnvRetentionDays, "30")
	later := now.Add(25 * time.Hour) // the old hour is now inside the store's lookahead
	for i := range 3 {
		a.tick(context.Background(), later.Add(time.Duration(i)*time.Minute))
	}
	if !exists(old.path(root, testNode)) {
		t.Fatalf("%s is inside the new retention and still in the store, but was not archived", old.FileName(testNode))
	}
}

// An ID that is not UTF-8 -- the client's X-Request-ID -- must match its own
// archived copy, or every merge adds the trace again.
func TestReconcile_DoesNotDuplicateAnIDThatIsNotUTF8(t *testing.T) {
	openStore(t)
	root := enableArchive(t)
	h := SegmentAt(time.Now().UTC().Add(-5 * time.Hour))
	store(t,
		testTrace{id: "\xff\xfe", at: h.Start().Add(10 * time.Minute)},
		testTrace{id: "y", at: h.Start().Add(20 * time.Minute)},
	)
	a := &Archiver{}
	for _, late := range []string{"late-1", "late-2"} {
		if _, err := a.reconcile(context.Background(), CurrentSettings(), h); err != nil {
			t.Fatal(err)
		}
		store(t, testTrace{id: late, at: h.Start().Add(30 * time.Minute)})
	}
	if _, err := a.reconcile(context.Background(), CurrentSettings(), h); err != nil {
		t.Fatal(err)
	}
	if got := ids(t, h.path(root, testNode)); len(got) != 4 {
		t.Fatalf("after three merges the hour holds %q, want four traces", got)
	}
}

// Traces stored before IDs were cleaned on the way in still hold raw bytes in
// their keys; the merge compares them as the archived JSON spells them.
func TestLineKeyOf_MatchesTheArchivedSpelling(t *testing.T) {
	at := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	raw := telemetry.AppendTraceKey(nil, at, "a\xff\xfeb")
	line, _ := json.Marshal(&telemetry.TraceRecord{ID: "a\xff\xfeb", Timestamp: at})
	fromLine, err := keyOfLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lineKeyOf(raw), fromLine.key) {
		t.Fatalf("store key %q reads as %q; the archived line keys as %q", raw, lineKeyOf(raw), fromLine.key)
	}
	valid := telemetry.AppendTraceKey(nil, at, "ok")
	if &lineKeyOf(valid)[0] != &valid[0] {
		t.Fatal("a valid key was copied; only an invalid one needs converting")
	}
}
