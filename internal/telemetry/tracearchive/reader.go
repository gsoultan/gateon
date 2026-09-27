// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry"
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
	// maxSearchHeld bounds what one search's archive sources hold at once.
	// Each holds the index of the file it is reading and one frame, compressed
	// and decoded, and a search has a source for every node with hours in its
	// period. Unbounded, what a search holds would be set by how many node
	// directories the archive root has and what their files claim -- on shared
	// storage, by any gateway that can write there. A frame is about a
	// megabyte and an index a few kilobytes: this is dozens of nodes.
	maxSearchHeld = 64 << 20
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
// any other failure to read it is an I/O error, and says nothing about the
// file. admit, if set, is told what the frame will take -- compressed and
// decoded -- before it is decoded, and may refuse it.
func (s *segmentFile) decodeFrame(i int, admit func(bytes int64) error) ([]byte, error) {
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
	if admit != nil {
		size, err := frameClaims(s.src)
		if err != nil {
			return nil, fmt.Errorf("%w: frame %d does not state its size", err, i)
		}
		if err := admit(size + int64(len(s.src))); err != nil {
			return nil, err
		}
	}
	if s.raw, err = dec.DecodeAll(s.src, s.raw[:0]); err != nil {
		return nil, fmt.Errorf("%w: frame %d: %w", ErrCorrupt, i, err)
	}
	return s.raw, nil
}

// frameClaims returns the size a zstd frame says it decodes to. The decoder
// holds a frame to its claim, so it can be counted before it is decoded; a
// frame that makes none is not one this package wrote.
func frameClaims(src []byte) (int64, error) {
	var h zstd.Header
	if h.Decode(src) != nil || !h.HasFCS || h.FrameContentSize > maxDecodedFrame {
		return 0, ErrCorrupt
	}
	return int64(h.FrameContentSize), nil // #nosec G115 -- at most maxDecodedFrame
}

// holdings is what one search's archive sources hold, against its limit. A
// search runs on one goroutine.
type holdings struct {
	n, limit int64
}

// resize changes what one source holds from *held to now bytes, unless growing
// would take the search past its limit.
func (h *holdings) resize(held *int64, now int64) error {
	if h == nil {
		return nil
	}
	if now > *held && h.n-*held+now > h.limit {
		return ErrTooLarge
	}
	h.n += now - *held
	*held = now
	return nil
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
		raw, err := s.decodeFrame(i, nil)
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
		if c.raw, err = c.s.decodeFrame(c.frame, nil); err != nil {
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

// archiveSource reads one node's archived traces in a window, in the window's
// direction, one at a time: the files in order, the frames of each that may
// hold the window, the lines of each frame. A search merges it with the store
// and with the other nodes' archives by key. A file that has gone -- retention
// runs while searches do -- or cannot be read is passed over: one bad file
// should not blank a year of history. What it holds is counted against the
// search's limit, and going past that ends the search.
type archiveSource struct {
	root string
	node string
	segs []segmentFileInfo // still to read, in scan order
	w    keyWindow
	hold *holdings
	held int64 // what this source holds, as counted in hold
	idx  int64 // of which, the open file's index

	f    *segmentFile
	a, b int // the open file's frames that may hold the window
	next int // frames of [a, b) decoded so far
	raw  []byte
	ends []int
	line int // lines of the current frame taken so far

	key  []byte
	rec  telemetry.TraceRecord
	size int
}

// advance moves to the next trace in the window and reports whether there is
// one.
func (s *archiveSource) advance(ctx context.Context) (bool, error) {
	for {
		if line, ok := s.nextLine(); ok {
			switch s.take(line) {
			case inWindow:
				return true, nil
			case pastWindow:
				s.close()
				s.segs = nil
				return false, nil
			}
			continue
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if ok, err := s.nextFrame(); !ok || err != nil {
			return false, err
		}
	}
}

func (s *archiveSource) current() ([]byte, *telemetry.TraceRecord, trace) {
	return s.key, &s.rec, trace{readable: true, size: s.size}
}

func (s *archiveSource) nodeName() string { return s.node }

// take reads a line's summary and places its key in the window. A line that
// cannot be read has no key to place, and is passed over.
func (s *archiveSource) take(line []byte) placement {
	s.rec = telemetry.TraceRecord{}
	if telemetry.UnmarshalTraceSummary(line, &s.rec) != nil {
		return beforeWindow
	}
	s.key = telemetry.AppendTraceKey(s.key[:0], s.rec.Timestamp, s.rec.ID)
	s.size = len(line)
	return s.w.place(s.key)
}

func (s *archiveSource) nextLine() ([]byte, bool) {
	for s.line < len(s.ends) {
		k := s.line
		if s.w.desc {
			k = len(s.ends) - 1 - s.line
		}
		s.line++
		start := 0
		if k > 0 {
			start = s.ends[k-1] + 1
		}
		if line := s.raw[start:s.ends[k]]; len(line) > 0 {
			return line, true
		}
	}
	return nil, false
}

// nextFrame decodes the next frame that may hold the window, opening the next
// file when the open one has none left. It reports false when every file is
// done, and an error only when the search may not hold what it would take.
func (s *archiveSource) nextFrame() (bool, error) {
	for {
		if s.f != nil && s.next < s.b-s.a {
			i := s.a + s.next
			if s.w.desc {
				i = s.b - 1 - s.next
			}
			s.next++
			raw, err := s.f.decodeFrame(i, s.admit)
			if errors.Is(err, ErrTooLarge) {
				return false, fmt.Errorf("%w: node %s", err, s.node)
			}
			if err != nil {
				logger.Default().LogWarn("trace archive: stopped reading a damaged segment",
					"node", s.node, "error", err)
				s.close()
				continue
			}
			s.raw, s.ends, s.line = raw, lineEnds(raw, s.ends), 0
			return true, nil
		}
		if ok, err := s.openNext(); !ok || err != nil {
			return false, err
		}
	}
}

// admit counts a frame about to be decoded, with the open file's index, in
// place of what the source held before.
func (s *archiveSource) admit(frame int64) error { return s.hold.resize(&s.held, s.idx+frame) }

func (s *archiveSource) openNext() (bool, error) {
	s.close()
	for len(s.segs) > 0 {
		info := s.segs[0]
		s.segs = s.segs[1:]
		f, err := openSegment(info.seg.path(s.root, s.node))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				logger.Default().LogWarn("trace archive: skipping an unreadable segment",
					"segment", info.seg.FileName(s.node), "error", err)
			}
			continue
		}
		idx := int64(len(f.frames)) * indexEntrySize
		if err := s.hold.resize(&s.held, idx); err != nil {
			_ = f.Close()
			return false, fmt.Errorf("%w: node %s", err, s.node)
		}
		nw := s.w.nanos()
		s.f, s.next, s.idx = f, 0, idx
		s.a, s.b = f.frameRange(nw.lo, nw.hi)
		return true, nil
	}
	return false, nil
}

// close closes the open file and gives back what the source held.
func (s *archiveSource) close() {
	if s.f != nil {
		_ = s.f.Close()
		s.f = nil
	}
	s.raw, s.ends, s.line, s.idx = nil, s.ends[:0], 0, 0
	_ = s.hold.resize(&s.held, 0)
}
