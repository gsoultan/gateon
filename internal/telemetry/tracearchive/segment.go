// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package tracearchive keeps traces after the live trace store lets them go.
//
// The live store (Pebble, in internal/telemetry) holds the last few days of
// traces. With archiving on, each hour of traces is copied out of it once the
// hour has closed, into one compressed file per hour, and the store may not
// delete an hour until the archive holds everything the store has for it.
// A query for a period reads the live store where it still has the traces and
// the archive where it does not, so the dashboard sees one timeline.
//
// On disk, in UTC:
//
//	<dir>/2026/09/26/traces-2026-09-26T14Z.ndjson.zst
//
// holds every trace whose request started in [14:00, 15:00) UTC on 26
// September 2026, one JSON object per line, zstd-compressed:
//
//	zstd -dc traces-2026-09-26T14Z.ndjson.zst | jq .path
//
// ADR-0022 records why the unit is an hour and the name is what it is.
package tracearchive

import (
	"errors"
	"path/filepath"
	"strings"
	"time"
)

const (
	segmentPrefix = "traces-"
	segmentSuffix = ".ndjson.zst"
	// stampLayout names the hour a segment holds. The trailing Z is a literal
	// -- Go reads a zone only as Z07, Z0700 or Z07:00 -- and says the hour is
	// UTC, so a name never means two different hours on either side of a
	// daylight-saving change.
	stampLayout = "2006-01-02T15Z"
)

// ErrNotASegment is returned for a name that is not exactly one Name produces.
var ErrNotASegment = errors.New("tracearchive: not an archive segment name")

// Segment is one UTC hour of traces: the unit the archive writes, names, keeps
// and deletes.
type Segment struct {
	start time.Time
}

// SegmentAt returns the segment that holds a trace whose request started at t.
func SegmentAt(t time.Time) Segment {
	return Segment{start: t.UTC().Truncate(time.Hour)}
}

// Start is the first instant the segment holds.
func (s Segment) Start() time.Time { return s.start }

// End is the first instant after it.
func (s Segment) End() time.Time { return s.start.Add(time.Hour) }

// Next is the hour after this one.
func (s Segment) Next() Segment { return Segment{start: s.End()} }

// Name is the segment's file name, e.g. traces-2026-09-26T14Z.ndjson.zst.
// Names sort in time order, and a glob on a prefix selects a day
// (traces-2026-09-26T*) or a month (traces-2026-09-*).
func (s Segment) Name() string {
	return segmentPrefix + s.start.Format(stampLayout) + segmentSuffix
}

// dir is the segment's directory below the archive root, e.g. 2026/09/26. A
// day is a directory so the tree can be copied, measured or deleted a day or
// a month at a time with ordinary tools.
func (s Segment) dir() string {
	return filepath.Join(s.start.Format("2006"), s.start.Format("01"), s.start.Format("02"))
}

func (s Segment) path(root string) string {
	return filepath.Join(root, s.dir(), s.Name())
}

// ParseSegmentName returns the segment a file name denotes. It accepts only
// the exact form Name produces, so a name that parses is also a single path
// component: no separator, no dot-dot, nothing a caller must clean first.
func ParseSegmentName(name string) (Segment, error) {
	stamp, ok := strings.CutPrefix(name, segmentPrefix)
	if ok {
		stamp, ok = strings.CutSuffix(stamp, segmentSuffix)
	}
	if !ok {
		return Segment{}, ErrNotASegment
	}
	t, err := time.Parse(stampLayout, stamp)
	if err != nil {
		return Segment{}, ErrNotASegment
	}
	seg := SegmentAt(t)
	if seg.Name() != name {
		return Segment{}, ErrNotASegment
	}
	return seg, nil
}
