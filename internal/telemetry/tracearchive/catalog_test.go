// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func names(segs []segmentFileInfo) []string {
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = s.seg.FileName(s.node)
	}
	return out
}

// plant writes a one-trace segment of testNode's for each hour.
func plant(t *testing.T, root string, stamps ...string) {
	t.Helper()
	for _, s := range stamps {
		seg := hour(t, s)
		writeFile(t, root, seg, testTrace{id: s, at: seg.Start().Add(time.Minute)})
	}
}

// dayDir is testNode's directory for a day, as the tests build it by hand.
func dayDir(root, y, m, d string) string { return filepath.Join(root, testNode, y, m, d) }

func TestListSegments_ReadsOnlyTheRangeAndOnlySegments(t *testing.T) {
	root := t.TempDir()
	plant(t, root, "2026-08-31T23", "2026-09-01T00", "2026-09-01T13", "2026-09-02T00", "2027-01-01T00")

	// Things that are not testNode's segments in their own day's directory.
	for _, junk := range []string{
		filepath.Join(dayDir(root, "2026", "09", "02"), hour(t, "2026-09-01T05").FileName(testNode)),   // wrong day
		filepath.Join(dayDir(root, "2026", "09", "01"), hour(t, "2026-09-01T08").FileName("gw-other")), // another node's
		filepath.Join(dayDir(root, "2026", "09", "01"), "notes.txt"),
		filepath.Join(dayDir(root, "2026", "13", "01"), hour(t, "2026-09-01T06").FileName(testNode)), // no month 13
		filepath.Join(dayDir(root, "2026", "09", "31"), hour(t, "2026-09-01T07").FileName(testNode)), // no 31 September
	} {
		if err := os.MkdirAll(filepath.Dir(junk), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(junk, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	all, err := listSegments(root, testNode, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"traces-2026-08-31T23Z.gw-test.ndjson.zst", "traces-2026-09-01T00Z.gw-test.ndjson.zst",
		"traces-2026-09-01T13Z.gw-test.ndjson.zst", "traces-2026-09-02T00Z.gw-test.ndjson.zst",
		"traces-2027-01-01T00Z.gw-test.ndjson.zst",
	}
	if got := names(all); !slices.Equal(got, want) {
		t.Fatalf("all segments = %v, want %v", got, want)
	}

	// [00:30, 13:00) on 1 September overlaps the 00:00 hour only.
	day := time.Date(2026, 9, 1, 0, 30, 0, 0, time.UTC)
	some, err := listSegments(root, testNode, day, day.Add(12*time.Hour+30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := names(some); !slices.Equal(got, want[1:2]) {
		t.Fatalf("segments in range = %v, want %v", got, want[1:2])
	}
}

// Every node's hours, ordered by hour and then node, and the nodes named once.
func TestListAllSegments_ReadsEveryNode(t *testing.T) {
	root := t.TempDir()
	h1, h2 := hour(t, "2026-09-26T10"), hour(t, "2026-09-26T11")
	writeNodeFile(t, root, "gw-b", h1, testTrace{id: "b1", at: h1.Start().Add(time.Minute)})
	writeNodeFile(t, root, "gw-a", h1, testTrace{id: "a1", at: h1.Start().Add(time.Minute)})
	writeNodeFile(t, root, "gw-a", h2, testTrace{id: "a2", at: h2.Start().Add(time.Minute)})
	if err := os.MkdirAll(filepath.Join(root, "Not A Node"), 0o750); err != nil {
		t.Fatal(err)
	}

	all, err := listAllSegments(root, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"traces-2026-09-26T10Z.gw-a.ndjson.zst", "traces-2026-09-26T10Z.gw-b.ndjson.zst",
		"traces-2026-09-26T11Z.gw-a.ndjson.zst",
	}
	if got := names(all); !slices.Equal(got, want) {
		t.Fatalf("all nodes' segments = %v, want %v", got, want)
	}
	st := statsOf(all, "gw-b")
	if !slices.Equal(st.nodes, []string{"gw-a", "gw-b"}) || st.own.segments != 1 || st.own.newest != h1 {
		t.Fatalf("stats = %+v; want both nodes, and gw-b's own hour", st)
	}
}

func TestListSegments_OnAMissingArchiveIsEmpty(t *testing.T) {
	segs, err := listSegments(filepath.Join(t.TempDir(), "never-written"), testNode, time.Time{}, time.Time{})
	if err != nil || len(segs) != 0 {
		t.Fatalf("listSegments = %v, %v; want nothing and no error", segs, err)
	}
}

func TestEnforceRetention_DropsExpiredHoursAndEmptyDirectories(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	plant(t, root, "2026-09-15T10", "2026-09-24T11", "2026-09-26T11")

	stats, err := enforceRetention(Settings{Dir: root, Node: testNode, RetentionDays: 7, MaxBytes: 1 << 30}, now)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := listSegments(root, testNode, time.Time{}, time.Time{})
	if got := names(left); !slices.Equal(got, []string{"traces-2026-09-24T11Z.gw-test.ndjson.zst", "traces-2026-09-26T11Z.gw-test.ndjson.zst"}) {
		t.Fatalf("kept %v", got)
	}
	if stats.segments != 2 || stats.oldest != hour(t, "2026-09-24T11") || stats.newest != hour(t, "2026-09-26T11") {
		t.Fatalf("stats = %+v", stats)
	}
	if exists(dayDir(root, "2026", "09", "15")) {
		t.Fatal("the emptied day directory was left behind")
	}
}

// A node that is renamed or replaced leaves its directory behind; retention
// ages it out, and takes the directory with its last hour.
func TestEnforceRetention_AgesOutAnotherNodesDirectory(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	gone := hour(t, "2026-09-10T10")
	writeNodeFile(t, root, "gw-retired", gone, testTrace{id: "r", at: gone.Start().Add(time.Minute)})
	plant(t, root, "2026-09-26T11")

	if _, err := enforceRetention(Settings{Dir: root, Node: testNode, RetentionDays: 7, MaxBytes: 1 << 30}, now); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(root, "gw-retired")) {
		t.Fatal("the retired node's expired hour, and its directory, were kept")
	}
	if left, _ := listSegments(root, testNode, time.Time{}, time.Time{}); len(left) != 1 {
		t.Fatalf("this node's own hour went too: %v", names(left))
	}
}

func TestEnforceRetention_SizeBudgetTakesTheOldestFirst(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	plant(t, root, "2026-09-26T08", "2026-09-26T09", "2026-09-26T10", "2026-09-26T11")
	all, _ := listSegments(root, testNode, time.Time{}, time.Time{})
	oneSize := all[0].size

	// Room for two and a half: the two newest stay.
	if _, err := enforceRetention(Settings{Dir: root, Node: testNode, RetentionDays: 30, MaxBytes: oneSize*2 + oneSize/2}, now); err != nil {
		t.Fatal(err)
	}
	left, _ := listSegments(root, testNode, time.Time{}, time.Time{})
	if got := names(left); !slices.Equal(got, []string{"traces-2026-09-26T10Z.gw-test.ndjson.zst", "traces-2026-09-26T11Z.gw-test.ndjson.zst"}) {
		t.Fatalf("kept %v, want the two newest", got)
	}
}

// One hour that will not delete must not be made up for with newer ones, or a
// single stuck file takes the whole archive with it.
func TestEnforceRetention_AStuckHourDoesNotTakeNewerOnes(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the permission that makes the file stuck")
	}
	root := t.TempDir()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	plant(t, root, "2026-09-25T08", "2026-09-26T09", "2026-09-26T10")
	stuckDir := dayDir(root, "2026", "09", "25")
	if err := os.Chmod(stuckDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stuckDir, 0o750) })

	if _, err := enforceRetention(Settings{Dir: root, Node: testNode, RetentionDays: 30, MaxBytes: 1}, now); err == nil {
		t.Fatal("a segment that could not be removed was not reported")
	}
	left, _ := listSegments(root, testNode, time.Time{}, time.Time{})
	if len(left) != 3 {
		t.Fatalf("kept %v; the newer hours were deleted to make up for the stuck one", names(left))
	}
}

func TestEnforceRetention_RemovesOnlyAbandonedTempFiles(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	dir := dayDir(root, "2026", "09", "26")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	abandoned := filepath.Join(dir, ".traces-2026-09-26T10Z.gw-test.ndjson.zst"+tempMarker+"1")
	fresh := filepath.Join(dir, ".traces-2026-09-26T11Z.gw-test.ndjson.zst"+tempMarker+"2")
	for _, p := range []string{abandoned, fresh} {
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := now.Add(-2 * staleTempAge)
	if err := os.Chtimes(abandoned, old, old); err != nil {
		t.Fatal(err)
	}

	if _, err := enforceRetention(Settings{Dir: root, Node: testNode, RetentionDays: 30, MaxBytes: 1 << 30}, now); err != nil {
		t.Fatal(err)
	}
	if exists(abandoned) {
		t.Fatal("an abandoned temporary file was kept")
	}
	if !exists(fresh) {
		t.Fatal("a file still being written was removed")
	}
}
