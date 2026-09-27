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
// On disk, in UTC, with a directory per gateway (ADR-0023):
//
//	<dir>/<node>/2026/09/26/traces-2026-09-26T14Z.<node>.ndjson.zst
//
// holds every trace whose request started in [14:00, 15:00) UTC on 26
// September 2026 at that node, one JSON object per line, zstd-compressed:
//
//	zstd -dc traces-2026-09-26T14Z.gw-1.ndjson.zst | jq .path
//
// ADR-0022 records why the unit is an hour and the name is what it is;
// ADR-0023 why each node has a directory, and every node reads them all.
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

// ErrNotASegment is returned for a name that is not exactly one FileName produces.
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

// FileName is the name of a node's file for the segment, e.g.
// traces-2026-09-26T14Z.gw-1.ndjson.zst. Names sort in time order, and a glob
// on a prefix selects a day (traces-2026-09-26T*) or a month (traces-2026-09-*).
// The node is in the name as well as the directory, so a file copied out of the
// tree -- a download is exactly that -- still says whose traces it holds.
func (s Segment) FileName(node string) string {
	return segmentPrefix + s.start.Format(stampLayout) + "." + node + segmentSuffix
}

// dir is the node's directory for the segment's day below the archive root,
// e.g. gw-1/2026/09/26. A day is a directory so the tree can be copied,
// measured or deleted a day or a month at a time with ordinary tools.
func (s Segment) dir(node string) string {
	return filepath.Join(node, s.start.Format("2006"), s.start.Format("01"), s.start.Format("02"))
}

func (s Segment) path(root, node string) string {
	return filepath.Join(root, s.dir(node), s.FileName(node))
}

// ParseFileName returns the segment and node a file name denotes. It accepts
// only the exact form FileName produces, with a node name ValidNode allows, so
// a name that parses is also a single path component: no separator, no
// dot-dot, nothing a caller must clean first.
func ParseFileName(name string) (Segment, string, error) {
	rest, ok := strings.CutPrefix(name, segmentPrefix)
	if ok {
		rest, ok = strings.CutSuffix(rest, segmentSuffix)
	}
	if !ok || len(rest) < len(stampLayout)+2 || rest[len(stampLayout)] != '.' {
		return Segment{}, "", ErrNotASegment
	}
	t, err := time.Parse(stampLayout, rest[:len(stampLayout)])
	node := rest[len(stampLayout)+1:]
	if err != nil || !ValidNode(node) {
		return Segment{}, "", ErrNotASegment
	}
	seg := SegmentAt(t)
	if seg.FileName(node) != name {
		return Segment{}, "", ErrNotASegment
	}
	return seg, node, nil
}

// maxNodeLen bounds a node's name: it is a directory and part of every file
// name, and a DNS label is as long as a host name gets.
const maxNodeLen = 63

// ValidNode reports whether s is a node name: lower-case letters, digits, '.',
// '_' and '-', not starting with a dot, at most 63 characters.
func ValidNode(s string) bool {
	if s == "" || len(s) > maxNodeLen || s[0] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !nodeChar(s[i]) {
			return false
		}
	}
	return true
}

func nodeChar(c byte) bool {
	return ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '.' || c == '_' || c == '-'
}

// NodeName turns a configured name or a host name into a valid node name:
// lower-cased, every other character replaced with '-', cut to 63. It starts
// at the first character that was already valid and is not a dot. What is
// left of nothing is "node".
func NodeName(s string) string {
	b := make([]byte, 0, min(len(s), maxNodeLen))
	for i := 0; i < len(s) && len(b) < maxNodeLen; i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if !nodeChar(c) {
			if len(b) == 0 {
				continue
			}
			c = '-'
		}
		if len(b) == 0 && c == '.' {
			continue
		}
		b = append(b, c)
	}
	if len(b) == 0 {
		return "node"
	}
	return string(b)
}
