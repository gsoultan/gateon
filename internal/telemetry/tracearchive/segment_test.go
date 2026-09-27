// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestSegmentName_IsTheUTCHour(t *testing.T) {
	// 20:15 in India is 14:45 UTC. A half-hour zone is the case a truncation
	// done in local time would get wrong.
	ist := time.FixedZone("IST", 5*3600+1800)
	seg := SegmentAt(time.Date(2026, 9, 26, 20, 15, 0, 0, ist))

	if got, want := seg.Name(), "traces-2026-09-26T14Z.ndjson.zst"; got != want {
		t.Fatalf("Name = %q, want %q", got, want)
	}
	if got, want := seg.dir(), filepath.Join("2026", "09", "26"); got != want {
		t.Fatalf("dir = %q, want %q", got, want)
	}
	if !seg.Start().Equal(time.Date(2026, 9, 26, 14, 0, 0, 0, time.UTC)) || seg.End().Sub(seg.Start()) != time.Hour {
		t.Fatalf("segment is [%v, %v), want the hour 14:00-15:00 UTC", seg.Start(), seg.End())
	}
}

func TestParseSegmentName_RoundTrips(t *testing.T) {
	for _, at := range []time.Time{
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(2028, 2, 29, 7, 30, 0, 0, time.UTC),
	} {
		seg := SegmentAt(at)
		got, err := ParseSegmentName(seg.Name())
		if err != nil || got != seg {
			t.Fatalf("ParseSegmentName(%q) = %v, %v; want %v", seg.Name(), got, err, seg)
		}
	}
}

// The name is the download endpoint's only input and becomes a path component.
// Anything but the exact form Name writes must be refused, not cleaned up.
func TestParseSegmentName_RefusesAnythingElse(t *testing.T) {
	for _, name := range []string{
		"",
		"traces-2026-09-26T14Z.ndjson.zst/../../../etc/passwd",
		"../traces-2026-09-26T14Z.ndjson.zst",
		"2026/09/26/traces-2026-09-26T14Z.ndjson.zst",
		"traces-2026-09-26T14.ndjson.zst",   // no zone: local time is ambiguous
		"traces-2026-09-26T14z.ndjson.zst",  // lower-case zone
		"traces-2026-9-26T14Z.ndjson.zst",   // unpadded month
		"traces-2026-09-26T24Z.ndjson.zst",  // no such hour
		"traces-2026-02-30T01Z.ndjson.zst",  // no such day
		"traces-2026-09-26T14Z.ndjson",      // not compressed
		"traces-2026-09-26T14Z.ndjson.zst ", // trailing space
		".traces-2026-09-26T14Z.ndjson.zst.tmp-123",
	} {
		if _, err := ParseSegmentName(name); !errors.Is(err, ErrNotASegment) {
			t.Errorf("ParseSegmentName(%q) = %v, want ErrNotASegment", name, err)
		}
	}
}

// Names sort in time order, across a day, a month and a year, so `ls`, a glob
// and a string sort all agree with the clock.
func TestSegmentNames_SortInTimeOrder(t *testing.T) {
	var segs []Segment
	for at := time.Date(2026, 12, 31, 20, 0, 0, 0, time.UTC); at.Before(time.Date(2027, 1, 1, 5, 0, 0, 0, time.UTC)); at = at.Add(time.Hour) {
		segs = append(segs, SegmentAt(at))
	}
	names := make([]string, len(segs))
	for i, s := range segs {
		names[i] = s.Name()
	}
	sorted := slices.Clone(names)
	slices.Reverse(sorted)
	slices.Sort(sorted)
	if !slices.Equal(names, sorted) {
		t.Fatalf("names out of time order:\n%v\nsorted:\n%v", names, sorted)
	}
}
