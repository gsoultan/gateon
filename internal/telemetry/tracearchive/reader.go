// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"

	"github.com/klauspost/compress/zstd"
)

const (
	// maxDecodedFrame bounds what decoding one frame may allocate. A frame
	// holds about frameTarget of NDJSON and at most one line past it, and the
	// headers and bodies in a line are bounded where they are captured, so
	// this is a ceiling against a damaged file, not a size a frame reaches.
	maxDecodedFrame = 256 << 20
	// maxIndexBytes bounds the index a reader loads: a million frames, a
	// terabyte of NDJSON in one hour. Anything larger is not a real index.
	maxIndexBytes = 32 << 20
	// decoderSlots is how many frames may be decoded at once across the
	// process. DecodeAll callers beyond it wait for a slot.
	decoderSlots = 2
)

// decoder is shared: DecodeAll may be called concurrently, up to decoderSlots
// at a time.
var decoder = sync.OnceValues(func() (*zstd.Decoder, error) {
	return zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(decoderSlots),
		zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxMemory(maxDecodedFrame))
})

// segmentFile is an open segment whose header and index have been read and
// checked. It is not safe for concurrent use: it decodes into its own buffers.
type segmentFile struct {
	f      *os.File
	meta   segmentMeta
	frames []frameEntry
	src    []byte // the compressed frame being decoded
	raw    []byte // its NDJSON
	ends   []int  // where each line of raw ends
}

func openSegment(path string) (*segmentFile, error) {
	f, err := os.Open(path) // #nosec G304 -- built from a parsed Segment under the archive root
	if err != nil {
		return nil, err
	}
	s, err := loadSegment(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return s, nil
}

func loadSegment(f *os.File) (*segmentFile, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < headerSize {
		return nil, ErrCorrupt
	}
	head := make([]byte, headerSize)
	if _, err := f.ReadAt(head, 0); err != nil {
		return nil, err
	}
	meta, err := decodeHeader(head)
	if err != nil {
		return nil, err
	}
	n := info.Size() - meta.IndexAt
	if n < skippableHeaderLen || n > maxIndexBytes {
		return nil, ErrCorrupt
	}
	index := make([]byte, n)
	if _, err := f.ReadAt(index, meta.IndexAt); err != nil {
		return nil, err
	}
	frames, err := decodeIndex(index, meta)
	if err != nil {
		return nil, err
	}
	return &segmentFile{f: f, meta: meta, frames: frames}, nil
}

func (s *segmentFile) Close() error { return s.f.Close() }

// readMeta reads a segment's header alone, which is all a listing needs.
func readMeta(path string) (segmentMeta, error) {
	f, err := os.Open(path) // #nosec G304 -- built from a parsed Segment under the archive root
	if err != nil {
		return segmentMeta{}, err
	}
	defer f.Close()
	head := make([]byte, headerSize)
	if _, err := io.ReadFull(f, head); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return segmentMeta{}, ErrCorrupt
		}
		return segmentMeta{}, err
	}
	return decodeHeader(head)
}

// frameRange returns the frames [a, b) that may hold traces started in
// [lo, hi), in Unix nanoseconds. Frames are in time order, so they are a run.
func (s *segmentFile) frameRange(lo, hi int64) (a, b int) {
	a = sort.Search(len(s.frames), func(i int) bool { return s.frames[i].last >= lo })
	b = sort.Search(len(s.frames), func(i int) bool { return s.frames[i].first >= hi })
	return a, max(a, b)
}

// decodeFrame returns frame i's NDJSON, valid until the next call. A frame
// that does not decode, or that the file is too short to hold, is ErrCorrupt;
// any other failure to read it is an I/O error, and says nothing about the file.
func (s *segmentFile) decodeFrame(i int) ([]byte, error) {
	dec, err := decoder()
	if err != nil {
		return nil, err
	}
	e := s.frames[i]
	if cap(s.src) < int(e.length) {
		s.src = make([]byte, e.length)
	}
	s.src = s.src[:e.length]
	if _, err := s.f.ReadAt(s.src, e.offset); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrCorrupt
		}
		return nil, err
	}
	if s.raw, err = dec.DecodeAll(s.src, s.raw[:0]); err != nil {
		return nil, fmt.Errorf("%w: frame %d: %w", ErrCorrupt, i, err)
	}
	return s.raw, nil
}

// scan visits each line of the frames that may hold traces started in
// [lo, hi), in key order or, if desc, reversed, until visit returns false.
// It reports whether visit was the one to stop it.
func (s *segmentFile) scan(ctx context.Context, w nanoWindow, visit func(line []byte) bool) (bool, error) {
	a, b := s.frameRange(w.lo, w.hi)
	for n := range b - a {
		i := a + n
		if w.desc {
			i = b - 1 - n
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		raw, err := s.decodeFrame(i)
		if err != nil {
			return false, err
		}
		if !s.eachLine(raw, w.desc, visit) {
			return true, nil
		}
	}
	return false, nil
}

// nanoWindow is a scan over [lo, hi) Unix nanoseconds, in one direction.
type nanoWindow struct {
	lo, hi int64
	desc   bool
}

// eachLine calls visit with each line of raw, last first if desc, and reports
// false as soon as visit does.
func (s *segmentFile) eachLine(raw []byte, desc bool, visit func(line []byte) bool) bool {
	s.ends = lineEnds(raw, s.ends)
	for n := range s.ends {
		k := n
		if desc {
			k = len(s.ends) - 1 - n
		}
		start := 0
		if k > 0 {
			start = s.ends[k-1] + 1
		}
		if line := raw[start:s.ends[k]]; len(line) > 0 && !visit(line) {
			return false
		}
	}
	return true
}

// lineEnds returns where each line of raw ends, reusing ends.
func lineEnds(raw []byte, ends []int) []int {
	ends = ends[:0]
	for off := 0; off < len(raw); {
		i := bytes.IndexByte(raw[off:], '\n')
		if i < 0 {
			return append(ends, len(raw))
		}
		ends = append(ends, off+i)
		off += i + 1
	}
	return ends
}

// lineCursor reads a segment's lines one at a time, in key order. The merge
// that folds late traces into an existing file pulls from it while the store
// pushes its own traces in the same order.
type lineCursor struct {
	s     *segmentFile
	frame int
	raw   []byte
	ends  []int
	line  int
}

func newLineCursor(s *segmentFile) *lineCursor { return &lineCursor{s: s} }

// next returns the next line, valid until the following call, or ok false at
// the end of the file.
func (c *lineCursor) next() (line []byte, ok bool, err error) {
	for c.line >= len(c.ends) {
		if c.frame >= len(c.s.frames) {
			return nil, false, nil
		}
		if c.raw, err = c.s.decodeFrame(c.frame); err != nil {
			return nil, false, err
		}
		c.frame++
		c.ends, c.line = lineEnds(c.raw, c.ends), 0
	}
	start := 0
	if c.line > 0 {
		start = c.ends[c.line-1] + 1
	}
	line = c.raw[start:c.ends[c.line]]
	c.line++
	return line, true, nil
}
