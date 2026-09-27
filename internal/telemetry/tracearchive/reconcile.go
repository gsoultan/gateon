// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/fs"
	"time"
	"unicode/utf8"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// reconcile makes seg's file hold everything the store holds for that hour. A
// file written against as many traces as the store holds now is left alone;
// otherwise a new one is written from the store and the old file together and
// replaces it. It reports whether it wrote a file.
func (a *Archiver) reconcile(ctx context.Context, s Settings, seg Segment) (bool, error) {
	old, err := openSegment(seg.path(s.Dir))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		old = nil
	case errors.Is(err, ErrCorrupt):
		// The store's copy is the best there is; what the file held that the
		// store does not, nothing can read.
		logger.Default().LogWarn("trace archive: replacing a damaged segment",
			"segment", seg.Name(), "error", err)
		old = nil
	case err != nil:
		// Not damage -- a permission, a descriptor limit, a failing disk. The
		// file may hold traces the store no longer has, so it is not replaced
		// on the strength of an error that says nothing about it; the next
		// tick tries again.
		return false, err
	default:
		defer old.Close()
		stored, err := countStored(ctx, seg)
		if err != nil {
			return false, err
		}
		if stored == old.meta.Stored {
			return false, nil
		}
	}
	return writeSegment(ctx, s.Dir, seg, old)
}

func countStored(ctx context.Context, seg Segment) (int64, error) {
	var n int64
	err := telemetry.ScanTraces(ctx, telemetry.TraceScan{From: seg.Start(), To: seg.End()},
		func(_, _ []byte) bool { n++; return true })
	return n, err
}

// writeSegment writes seg from the store's traces merged with old's, in key
// order; a trace in both is taken from the store. old may be nil.
func writeSegment(ctx context.Context, root string, seg Segment, old *segmentFile) (bool, error) {
	w, err := newSegmentWriter(root, seg)
	if err != nil {
		return false, err
	}
	m := &merger{w: w}
	if old != nil {
		m.old = newLineCursor(old)
	}
	err = telemetry.ScanTraces(ctx, telemetry.TraceScan{From: seg.Start(), To: seg.End()}, m.stored)
	err = errors.Join(err, m.err)
	if err == nil {
		err = m.drainOld(nil)
	}
	if err != nil {
		w.abort()
		return false, err
	}
	meta, published, err := w.commit()
	if published {
		segmentsWritten.Inc()
		tracesWritten.Add(float64(meta.Count))
	}
	return published, err
}

// merger feeds a segment writer from two sources in key order: the store,
// which pushes its traces through stored, and an existing file, which it pulls
// from as far as each stored trace.
type merger struct {
	w       *segmentWriter
	old     *lineCursor
	pending *oldLine
	err     error
}

// oldLine is the existing file's next line, with the key it sorts by.
type oldLine struct {
	key  []byte
	line []byte
	ts   int64
}

// stored takes one of the store's traces as it stands: the JSON the store
// wrote, credential headers already redacted by it, so the archive is a copy
// of the store and exporting costs compression and nothing else. A value that
// is not one line would not be one NDJSON record, and is counted and left out.
func (m *merger) stored(key, value []byte) bool {
	if m.err = m.drainOld(lineKeyOf(key)); m.err != nil {
		return false
	}
	unusable := len(value) == 0 || bytes.IndexByte(value, '\n') >= 0
	m.w.fromStore(unusable)
	if unusable {
		return true
	}
	m.err = m.w.add(value, int64(binary.BigEndian.Uint64(key[:8])))
	return m.err == nil
}

// drainOld writes the existing file's lines that sort before until, and drops
// the one equal to it, which the store's copy replaces. A nil until drains the
// file.
func (m *merger) drainOld(until []byte) error {
	for {
		if err := m.peek(); err != nil || m.pending == nil {
			return err
		}
		if until != nil {
			c := bytes.Compare(m.pending.key, until)
			if c > 0 {
				return nil
			}
			if c == 0 {
				m.pending = nil
				continue
			}
		}
		if err := m.w.add(m.pending.line, m.pending.ts); err != nil {
			return err
		}
		m.pending = nil
	}
}

// peek loads the existing file's next line into pending. A file found damaged
// part-way is abandoned there rather than failing the merge: the store's
// traces for the hour are still worth keeping, and nothing can read the rest.
// Any other read error fails the merge, which the next tick retries, because
// the rest of the file may be fine and hold traces the store no longer has.
func (m *merger) peek() error {
	for m.pending == nil && m.old != nil {
		line, ok, err := m.old.next()
		if err != nil && !errors.Is(err, ErrCorrupt) {
			return err
		}
		if err != nil {
			logger.Default().LogWarn("trace archive: stopped reading a damaged segment part-way",
				"error", err)
		}
		if err != nil || !ok {
			m.old = nil
			return nil
		}
		if p, err := keyOfLine(line); err == nil {
			m.pending = p
		}
	}
	return nil
}

// lineKeyOf returns a store key as the key of the archived line would read.
// The two differ only for an ID that is not UTF-8 -- stored before IDs were
// cleaned on the way in -- which the line's JSON holds with U+FFFD for each
// bad byte. Compared unconverted, such a trace would never match its own
// archived copy, and every merge would add it again.
func lineKeyOf(key []byte) []byte {
	if len(key) < 9 || utf8.Valid(key[9:]) {
		return key
	}
	asJSON, _ := json.Marshal(string(key[9:]))
	var id string
	_ = json.Unmarshal(asJSON, &id)
	return append(append([]byte(nil), key[:9]...), id...)
}

// keyOfLine reads the start time and ID of an archived trace, which is all it
// takes to place it among the store's.
func keyOfLine(line []byte) (*oldLine, error) {
	var probe struct {
		ID        string    `json:"id"`
		Timestamp time.Time `json:"timestamp"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return nil, err
	}
	return &oldLine{
		key:  telemetry.AppendTraceKey(nil, probe.Timestamp, probe.ID),
		line: line,
		ts:   probe.Timestamp.UnixNano(),
	}, nil
}
