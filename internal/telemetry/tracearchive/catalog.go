// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// segmentFileInfo is a segment found on disk.
type segmentFileInfo struct {
	seg  Segment
	size int64
	mod  time.Time
}

// staleTempAge is how old a leftover temporary file must be before the
// retention pass removes it. A segment being written is younger than this by
// orders of magnitude; one this old was abandoned by a crash.
const staleTempAge = time.Hour

// periodLevels are the directories below the archive root -- year, month,
// day -- with the layout of each one's name and the length of its period.
var periodLevels = [...]struct {
	layout string
	next   func(time.Time) time.Time
}{
	{"2006", func(t time.Time) time.Time { return t.AddDate(1, 0, 0) }},
	{"01", func(t time.Time) time.Time { return t.AddDate(0, 1, 0) }},
	{"02", func(t time.Time) time.Time { return t.AddDate(0, 0, 1) }},
}

// segmentWalk lists the segments under root that overlap [from, to), oldest
// first. A zero bound is open. Directories whose period lies outside the
// range are not opened, so a query for one day reads one day's directory.
// Anything in the tree that is not a segment in its own day's directory is
// ignored, except abandoned temporary files, which are collected for removal.
type segmentWalk struct {
	root     string
	from, to time.Time
	segments []segmentFileInfo
	temps    []string
}

func listSegments(root string, from, to time.Time) ([]segmentFileInfo, error) {
	w := segmentWalk{root: root, from: from, to: to}
	err := w.walk("", 0, time.Time{})
	return w.segments, err
}

func (w *segmentWalk) walk(rel string, depth int, parent time.Time) error {
	entries, err := os.ReadDir(filepath.Join(w.root, rel))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if depth == len(periodLevels) {
		w.collect(rel, entries)
		return nil
	}
	for _, e := range entries { // ReadDir sorts by name, which is by time here
		start, ok := childPeriod(parent, depth, e)
		if !ok || !w.overlaps(start, periodLevels[depth].next(start)) {
			continue
		}
		if err := w.walk(filepath.Join(rel, e.Name()), depth+1, start); err != nil {
			return err
		}
	}
	return nil
}

// childPeriod returns when the period a directory names starts, if it is a
// directory named the one way its level allows.
func childPeriod(parent time.Time, depth int, e fs.DirEntry) (time.Time, bool) {
	if !e.IsDir() {
		return time.Time{}, false
	}
	layout := periodLevels[depth].layout
	t, err := time.Parse(layout, e.Name())
	if err != nil {
		return time.Time{}, false
	}
	switch depth {
	case 1:
		t = time.Date(parent.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	case 2:
		t = time.Date(parent.Year(), parent.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	}
	// 31 in a thirty-day month parses, then normalises into the next month.
	return t, t.Format(layout) == e.Name()
}

func (w *segmentWalk) overlaps(start, end time.Time) bool {
	return (w.to.IsZero() || start.Before(w.to)) && (w.from.IsZero() || end.After(w.from))
}

func (w *segmentWalk) collect(rel string, entries []fs.DirEntry) {
	for _, e := range entries {
		if strings.Contains(e.Name(), tempMarker) {
			w.temps = append(w.temps, filepath.Join(rel, e.Name()))
			continue
		}
		seg, err := ParseSegmentName(e.Name())
		if err != nil || !e.Type().IsRegular() || seg.dir() != rel || !w.overlaps(seg.Start(), seg.End()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		w.segments = append(w.segments, segmentFileInfo{seg: seg, size: info.Size(), mod: info.ModTime()})
	}
}

// catalogStats summarises what the archive holds.
type catalogStats struct {
	segments int
	bytes    int64
	oldest   Segment
	newest   Segment
}

func statsOf(segs []segmentFileInfo) catalogStats {
	st := catalogStats{segments: len(segs)}
	for _, s := range segs {
		st.bytes += s.size
	}
	if len(segs) > 0 {
		st.oldest, st.newest = segs[0].seg, segs[len(segs)-1].seg
	}
	return st
}

// enforceRetention deletes the segments past the retention age, then the
// oldest ones until the archive fits its size budget, then whatever an
// interrupted write left behind. It returns what remains.
//
// An hour that will not delete stops the size eviction for this pass rather
// than being made up for with newer ones: one unremovable file would otherwise
// take the whole archive with it, newest last.
func enforceRetention(s Settings, now time.Time) (catalogStats, error) {
	w := segmentWalk{root: s.Dir}
	if err := w.walk("", 0, time.Time{}); err != nil {
		return catalogStats{}, err
	}
	cutoff := now.AddDate(0, 0, -max(s.RetentionDays, 1))
	total := int64(0)
	for _, info := range w.segments {
		total += info.size
	}
	keep := make([]segmentFileInfo, 0, len(w.segments))
	var firstErr error
	stuck := false
	for _, info := range w.segments {
		expired := !info.seg.End().After(cutoff)
		over := s.MaxBytes > 0 && total > s.MaxBytes && !stuck
		if !expired && !over {
			keep = append(keep, info)
			continue
		}
		if err := removeSegment(s.Dir, info.seg); err != nil {
			firstErr = cmpErr(firstErr, err)
			keep = append(keep, info)
			stuck = true
			continue
		}
		total -= info.size
	}
	w.removeStaleTemps(now)
	return statsOf(keep), firstErr
}

func cmpErr(first, err error) error {
	if first != nil {
		return first
	}
	return err
}

// removeSegment deletes a segment and then its day, month and year
// directories, each only if that left it empty.
func removeSegment(root string, seg Segment) error {
	if err := os.Remove(seg.path(root)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for dir := seg.dir(); dir != "." && dir != ""; dir = filepath.Dir(dir) {
		if os.Remove(filepath.Join(root, dir)) != nil {
			break // not empty, which is the usual answer
		}
	}
	return nil
}

func (w *segmentWalk) removeStaleTemps(now time.Time) {
	for _, rel := range w.temps {
		path := filepath.Join(w.root, rel)
		if info, err := os.Lstat(path); err == nil && now.Sub(info.ModTime()) > staleTempAge {
			_ = os.Remove(path)
		}
	}
}
