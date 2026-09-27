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
		out[i] = s.seg.Name()
	}
	return out
}

// plant writes a one-trace segment for each hour.
func plant(t *testing.T, root string, stamps ...string) {
	t.Helper()
	for _, s := range stamps {
		seg := hour(t, s)
		writeFile(t, root, seg, testTrace{id: s, at: seg.Start().Add(time.Minute)})
	}
}

func TestListSegments_ReadsOnlyTheRangeAndOnlySegments(t *testing.T) {
	root := t.TempDir()
	plant(t, root, "2026-08-31T23", "2026-09-01T00", "2026-09-01T13", "2026-09-02T00", "2027-01-01T00")

	// Things that are not segments in their own day's directory.
	misplaced := filepath.Join(root, "2026", "09", "02", hour(t, "2026-09-01T05").Name())
	for _, junk := range []string{
		misplaced,
		filepath.Join(root, "2026", "09", "01", "notes.txt"),
		filepath.Join(root, "2026", "13", "01", hour(t, "2026-09-01T06").Name()), // no month 13
		filepath.Join(root, "2026", "09", "31", hour(t, "2026-09-01T07").Name()), // no 31 September
	} {
		if err := os.MkdirAll(filepath.Dir(junk), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(junk, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	all, err := listSegments(root, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"traces-2026-08-31T23Z.ndjson.zst", "traces-2026-09-01T00Z.ndjson.zst", "traces-2026-09-01T13Z.ndjson.zst",
		"traces-2026-09-02T00Z.ndjson.zst", "traces-2027-01-01T00Z.ndjson.zst",
	}
	if got := names(all); !slices.Equal(got, want) {
		t.Fatalf("all segments = %v, want %v", got, want)
	}

	// [00:30, 13:00) on 1 September overlaps the 00:00 hour only.
	day := time.Date(2026, 9, 1, 0, 30, 0, 0, time.UTC)
	some, err := listSegments(root, day, day.Add(12*time.Hour+30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := names(some); !slices.Equal(got, want[1:2]) {
		t.Fatalf("segments in range = %v, want %v", got, want[1:2])
	}
}

func TestListSegments_OnAMissingArchiveIsEmpty(t *testing.T) {
	segs, err := listSegments(filepath.Join(t.TempDir(), "never-written"), time.Time{}, time.Time{})
	if err != nil || len(segs) != 0 {
		t.Fatalf("listSegments = %v, %v; want nothing and no error", segs, err)
	}
}

func TestEnforceRetention_DropsExpiredHoursAndEmptyDirectories(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	plant(t, root, "2026-09-15T10", "2026-09-24T11", "2026-09-26T11")

	stats, err := enforceRetention(Settings{Dir: root, RetentionDays: 7, MaxBytes: 1 << 30}, now)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := listSegments(root, time.Time{}, time.Time{})
	if got := names(left); !slices.Equal(got, []string{"traces-2026-09-24T11Z.ndjson.zst", "traces-2026-09-26T11Z.ndjson.zst"}) {
		t.Fatalf("kept %v", got)
	}
	if stats.segments != 2 || stats.oldest != hour(t, "2026-09-24T11") || stats.newest != hour(t, "2026-09-26T11") {
		t.Fatalf("stats = %+v", stats)
	}
	if exists(filepath.Join(root, "2026", "09", "15")) {
		t.Fatal("the emptied day directory was left behind")
	}
}

func TestEnforceRetention_SizeBudgetTakesTheOldestFirst(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	plant(t, root, "2026-09-26T08", "2026-09-26T09", "2026-09-26T10", "2026-09-26T11")
	all, _ := listSegments(root, time.Time{}, time.Time{})
	oneSize := all[0].size

	// Room for two and a half: the two newest stay.
	if _, err := enforceRetention(Settings{Dir: root, RetentionDays: 30, MaxBytes: oneSize*2 + oneSize/2}, now); err != nil {
		t.Fatal(err)
	}
	left, _ := listSegments(root, time.Time{}, time.Time{})
	if got := names(left); !slices.Equal(got, []string{"traces-2026-09-26T10Z.ndjson.zst", "traces-2026-09-26T11Z.ndjson.zst"}) {
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
	stuckDir := filepath.Join(root, "2026", "09", "25")
	if err := os.Chmod(stuckDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stuckDir, 0o750) })

	if _, err := enforceRetention(Settings{Dir: root, RetentionDays: 30, MaxBytes: 1}, now); err == nil {
		t.Fatal("a segment that could not be removed was not reported")
	}
	left, _ := listSegments(root, time.Time{}, time.Time{})
	if len(left) != 3 {
		t.Fatalf("kept %v; the newer hours were deleted to make up for the stuck one", names(left))
	}
}

func TestEnforceRetention_RemovesOnlyAbandonedTempFiles(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	dir := filepath.Join(root, "2026", "09", "26")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	abandoned := filepath.Join(dir, ".traces-2026-09-26T10Z.ndjson.zst"+tempMarker+"1")
	fresh := filepath.Join(dir, ".traces-2026-09-26T11Z.ndjson.zst"+tempMarker+"2")
	for _, p := range []string{abandoned, fresh} {
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := now.Add(-2 * staleTempAge)
	if err := os.Chtimes(abandoned, old, old); err != nil {
		t.Fatal(err)
	}

	if _, err := enforceRetention(Settings{Dir: root, RetentionDays: 30, MaxBytes: 1 << 30}, now); err != nil {
		t.Fatal(err)
	}
	if exists(abandoned) {
		t.Fatal("an abandoned temporary file was kept")
	}
	if !exists(fresh) {
		t.Fatal("a file still being written was removed")
	}
}
