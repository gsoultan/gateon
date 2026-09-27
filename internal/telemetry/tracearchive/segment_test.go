// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestFileName_IsTheUTCHourAndTheNode(t *testing.T) {
	// 20:15 in India is 14:45 UTC. A half-hour zone is the case a truncation
	// done in local time would get wrong.
	ist := time.FixedZone("IST", 5*3600+1800)
	seg := SegmentAt(time.Date(2026, 9, 26, 20, 15, 0, 0, ist))

	if got, want := seg.FileName("gw-1"), "traces-2026-09-26T14Z.gw-1.ndjson.zst"; got != want {
		t.Fatalf("FileName = %q, want %q", got, want)
	}
	if got, want := seg.dir("gw-1"), filepath.Join("gw-1", "2026", "09", "26"); got != want {
		t.Fatalf("dir = %q, want %q", got, want)
	}
	if !seg.Start().Equal(time.Date(2026, 9, 26, 14, 0, 0, 0, time.UTC)) || seg.End().Sub(seg.Start()) != time.Hour {
		t.Fatalf("segment is [%v, %v), want the hour 14:00-15:00 UTC", seg.Start(), seg.End())
	}
}

func TestParseFileName_RoundTrips(t *testing.T) {
	for _, at := range []time.Time{
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(2028, 2, 29, 7, 30, 0, 0, time.UTC),
	} {
		for _, node := range []string{"gw-1", "ip-10-0-1-23.ec2.internal", "a", "node_7"} {
			seg := SegmentAt(at)
			got, gotNode, err := ParseFileName(seg.FileName(node))
			if err != nil || got != seg || gotNode != node {
				t.Fatalf("ParseFileName(%q) = %v, %q, %v; want %v, %q", seg.FileName(node), got, gotNode, err, seg, node)
			}
		}
	}
}

// The name is the download endpoint's only input and becomes two path
// components: the node's directory and the file. Anything but the exact form
// FileName writes must be refused, not cleaned up.
func TestParseFileName_RefusesAnythingElse(t *testing.T) {
	for _, name := range []string{
		"",
		"traces-2026-09-26T14Z.ndjson.zst",  // no node
		"traces-2026-09-26T14Z..ndjson.zst", // empty node
		"traces-2026-09-26T14Z.../etc.ndjson.zst",                          // a node that is a path
		"traces-2026-09-26T14Z.gw/1.ndjson.zst",                            // a separator in the node
		"traces-2026-09-26T14Z..hidden.ndjson.zst",                         // a node starting with a dot
		"traces-2026-09-26T14Z.GW-1.ndjson.zst",                            // upper case
		"traces-2026-09-26T14Z." + strings.Repeat("n", 64) + ".ndjson.zst", // too long
		"../traces-2026-09-26T14Z.gw-1.ndjson.zst",
		"gw-1/2026/09/26/traces-2026-09-26T14Z.gw-1.ndjson.zst",
		"traces-2026-09-26T14.gw-1.ndjson.zst",  // no zone: local time is ambiguous
		"traces-2026-9-26T14Z.gw-1.ndjson.zst",  // unpadded month
		"traces-2026-09-26T24Z.gw-1.ndjson.zst", // no such hour
		"traces-2026-02-30T01Z.gw-1.ndjson.zst", // no such day
		"traces-2026-09-26T14Z.gw-1.ndjson",     // not compressed
		".traces-2026-09-26T14Z.gw-1.ndjson.zst.tmp-123",
	} {
		if _, _, err := ParseFileName(name); !errors.Is(err, ErrNotASegment) {
			t.Errorf("ParseFileName(%q) = %v, want ErrNotASegment", name, err)
		}
	}
}

// Whatever a host is called, the node's name is a safe single path component.
func TestNodeName_MakesAnyNameSafe(t *testing.T) {
	for in, want := range map[string]string{
		"gw-1":                      "gw-1",
		"GW-Eu-1":                   "gw-eu-1",
		"ip-10-0-1-23.ec2.internal": "ip-10-0-1-23.ec2.internal",
		"../../etc":                 "etc",
		"a/b":                       "a-b",
		".hidden":                   "hidden",
		"":                          "node",
		"///":                       "node",
		strings.Repeat("x", 100):    strings.Repeat("x", 63),
		"pod name with spaces":      "pod-name-with-spaces",
	} {
		got := NodeName(in)
		if got != want || !ValidNode(got) {
			t.Errorf("NodeName(%q) = %q (valid %v), want %q", in, got, ValidNode(got), want)
		}
	}
}

// Names sort in time order, across a day, a month and a year, so `ls`, a glob
// and a string sort all agree with the clock.
func TestFileNames_SortInTimeOrder(t *testing.T) {
	var segs []Segment
	for at := time.Date(2026, 12, 31, 20, 0, 0, 0, time.UTC); at.Before(time.Date(2027, 1, 1, 5, 0, 0, 0, time.UTC)); at = at.Add(time.Hour) {
		segs = append(segs, SegmentAt(at))
	}
	names := make([]string, len(segs))
	for i, s := range segs {
		names[i] = s.FileName("gw-1")
	}
	sorted := slices.Clone(names)
	slices.Reverse(sorted)
	slices.Sort(sorted)
	if !slices.Equal(names, sorted) {
		t.Fatalf("names out of time order:\n%v\nsorted:\n%v", names, sorted)
	}
}
