// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"bytes"
	"hash/crc32"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	// dirPerm and the 0600 os.CreateTemp gives each file: an archive holds
	// captured request data, which is not for every local account to read.
	dirPerm = 0o750
	// tempMarker is in the name of a segment still being written. A crash
	// mid-write leaves one behind; the retention pass removes it.
	tempMarker = ".tmp-"
)

// encoder is shared: EncodeAll may be called concurrently, and each call runs
// on the calling goroutine alone.
var encoder = sync.OnceValues(func() (*zstd.Encoder, error) {
	return zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderConcurrency(1),
		zstd.WithLowerEncoderMem(true))
})

// segmentWriter writes one segment file. It is handed traces in key order and
// publishes the file only once every one of them is on disk: until commit the
// file has a temporary name, and any failure removes it. A truncated archive
// that looks complete is worse than none -- it is what the store's traces are
// deleted on the strength of.
type segmentWriter struct {
	final  string
	tmp    string
	f      *os.File
	enc    *zstd.Encoder
	buf    []byte // NDJSON of the frame being filled
	zbuf   []byte
	at     int64 // where the next frame starts
	cur    frameEntry
	frames []frameEntry
	meta   segmentMeta
}

func newSegmentWriter(root, node string, seg Segment) (*segmentWriter, error) {
	enc, err := encoder()
	if err != nil {
		return nil, err
	}
	final := seg.path(root, node)
	if err := os.MkdirAll(filepath.Dir(final), dirPerm); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(final), "."+seg.FileName(node)+tempMarker+"*")
	if err != nil {
		return nil, err
	}
	w := &segmentWriter{final: final, tmp: f.Name(), f: f, enc: enc, at: headerSize}
	w.meta = segmentMeta{Format: formatName, Version: formatVersion, Node: node, Start: seg.Start(), End: seg.End()}
	// A placeholder the size of the real header, so the data frames land where
	// the index will say they are.
	if _, err := f.Write(bytes.Repeat([]byte{0}, headerSize)); err != nil {
		w.abort()
		return nil, err
	}
	return w, nil
}

// add appends one trace's JSON line; ts is its start time in Unix nanoseconds.
func (w *segmentWriter) add(line []byte, ts int64) error {
	if len(w.buf) > 0 && len(w.buf)+len(line)+1 > frameTarget {
		if err := w.flushFrame(); err != nil {
			return err
		}
	}
	if w.cur.count == 0 {
		w.cur.first = ts
	}
	w.cur.last = ts
	w.cur.count++
	w.buf = append(append(w.buf, line...), '\n')
	return nil
}

// fromStore counts a trace the store held for the hour; skipped says it could
// not be read and so was not added.
func (w *segmentWriter) fromStore(skipped bool) {
	w.meta.Stored++
	if skipped {
		w.meta.Skipped++
	}
}

func (w *segmentWriter) flushFrame() error {
	if w.cur.count == 0 {
		return nil
	}
	w.zbuf = w.enc.EncodeAll(w.buf, w.zbuf[:0])
	if _, err := w.f.Write(w.zbuf); err != nil {
		return err
	}
	w.cur.offset, w.cur.length = w.at, uint32(len(w.zbuf))
	w.frames = append(w.frames, w.cur)
	w.at += int64(len(w.zbuf))
	w.meta.Count += int64(w.cur.count)
	w.meta.RawBytes += int64(len(w.buf))
	w.cur, w.buf = frameEntry{}, w.buf[:0]
	return nil
}

// commit finishes the file and puts it in place, replacing any earlier file
// for the same hour. A writer that was given no traces publishes nothing; it
// reports published false and leaves an existing file alone.
func (w *segmentWriter) commit() (meta segmentMeta, published bool, err error) {
	if err := w.flushFrame(); err != nil {
		w.abort()
		return segmentMeta{}, false, err
	}
	if len(w.frames) == 0 {
		w.abort()
		return w.meta, false, nil
	}
	w.meta.Frames = len(w.frames)
	w.meta.First = time.Unix(0, w.frames[0].first).UTC()
	w.meta.Last = time.Unix(0, w.frames[len(w.frames)-1].last).UTC()
	w.meta.IndexAt = w.at
	w.meta.Created = time.Now().UTC().Truncate(time.Second)
	if err := w.finish(); err != nil {
		w.abort()
		return segmentMeta{}, false, err
	}
	return w.meta, true, nil
}

func (w *segmentWriter) finish() error {
	index := encodeIndex(w.frames)
	w.meta.IndexCRC = crc32.ChecksumIEEE(index)
	header, err := encodeHeader(w.meta)
	if err != nil {
		return err
	}
	if _, err := w.f.Write(index); err != nil {
		return err
	}
	if _, err := w.f.WriteAt(header, 0); err != nil {
		return err
	}
	// Synced before the rename, so the name never points at data that a power
	// cut could still take back.
	if err := w.f.Sync(); err != nil {
		return err
	}
	err = w.f.Close()
	w.f = nil
	if err != nil {
		return err
	}
	if err := os.Rename(w.tmp, w.final); err != nil {
		return err
	}
	syncDir(filepath.Dir(w.final))
	return nil
}

// abort discards the file being written.
func (w *segmentWriter) abort() {
	if w.f != nil {
		_ = w.f.Close()
		w.f = nil
	}
	_ = os.Remove(w.tmp)
}

// syncDir makes a rename in dir durable. It is best effort: where a platform
// cannot sync a directory, the rename is still in place, only less certain to
// survive a power cut, and nothing the caller could do differs.
func syncDir(dir string) {
	d, err := os.Open(dir) // #nosec G304 -- dir is the archive's own day directory
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
