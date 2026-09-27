// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

const (
	defaultListLimit = 48 // two days of hours
	maxListLimit     = 200
	// maxDownloads bounds the hours being sent at once. Each holds a file and,
	// decompressing, a frame; a client that opens many and reads none would
	// otherwise hold them for as long as it liked.
	maxDownloads = 4
)

var downloadSlots = make(chan struct{}, maxDownloads)

// Lookup returns the archived trace with this start time and ID, in full, or
// nil if the archive does not hold it. The start time names the hour and,
// through the index, the frame; only that frame is decoded.
func Lookup(ctx context.Context, ts time.Time, id string) (*telemetry.TraceRecord, error) {
	f, err := openSegment(SegmentAt(ts).path(CurrentSettings().Dir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// The ID as the archive's JSON spells it, to pass over the lines that
	// cannot be the one without decoding them.
	needle, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}
	var found *telemetry.TraceRecord
	at := ts.UnixNano()
	_, err = f.scan(ctx, nanoWindow{lo: at, hi: at + 1}, func(line []byte) bool {
		if !bytes.Contains(line, needle) {
			return true
		}
		var rec telemetry.TraceRecord
		if json.Unmarshal(line, &rec) != nil || rec.ID != id || !rec.Timestamp.Equal(ts) {
			return true
		}
		found = &rec
		return false
	})
	return found, err
}

// SegmentSummary is one archived hour, as a listing shows it.
type SegmentSummary struct {
	Segment  Segment
	Size     int64
	Traces   int64
	Archived time.Time
}

// List returns the archived hours that overlap [from, to), newest first, a
// page at a time. A zero bound is open. pageToken is the next token the page
// before returned; the token is the name of that page's last hour.
func List(from, to time.Time, limit int, pageToken string) ([]SegmentSummary, string, error) {
	if pageToken != "" {
		seg, err := ParseSegmentName(pageToken)
		if err != nil {
			return nil, "", fmt.Errorf("%w: the page token is not one this server issued", ErrInvalidQuery)
		}
		if to.IsZero() || seg.start.Before(to) {
			to = seg.start
		}
	}
	root := CurrentSettings().Dir
	segs, err := listSegments(root, from, to)
	if err != nil {
		return nil, "", err
	}
	slices.Reverse(segs)
	limit = min(cmpOr(limit, defaultListLimit), maxListLimit)
	next := ""
	if len(segs) > limit {
		segs = segs[:limit]
		next = segs[limit-1].seg.Name()
	}
	out := make([]SegmentSummary, 0, len(segs))
	for _, info := range segs {
		sum := SegmentSummary{Segment: info.seg, Size: info.size, Archived: info.mod}
		if m, err := readMeta(info.seg.path(root)); err == nil {
			sum.Traces, sum.Archived = m.Count, m.Created
		}
		out = append(out, sum)
	}
	return out, next, nil
}

// Download is an archived hour opened for sending to a client. It holds one
// of maxDownloads slots until it is closed.
type Download struct {
	Name    string
	ModTime time.Time
	file    *segmentFile
	release sync.Once
}

// OpenDownload opens the archived hour a file name names. The name is the only
// input, and only the exact form Segment.Name produces is accepted, so it
// cannot reach outside the archive. With maxDownloads already open it returns
// ErrBusy at once rather than queueing.
func OpenDownload(name string) (*Download, error) {
	seg, err := ParseSegmentName(name)
	if err != nil {
		return nil, err
	}
	select {
	case downloadSlots <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	d, err := openDownload(seg)
	if err != nil {
		<-downloadSlots
		return nil, err
	}
	return d, nil
}

func openDownload(seg Segment) (*Download, error) {
	f, err := openSegment(seg.path(CurrentSettings().Dir))
	if err != nil {
		return nil, err
	}
	info, err := f.f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Download{Name: seg.Name(), ModTime: info.ModTime(), file: f}, nil
}

// Content is the file as stored -- zstd, readable with `zstd -dc` -- for
// http.ServeContent.
func (d *Download) Content() io.ReadSeeker { return d.file.f }

// WriteNDJSON writes the hour's traces decompressed, one JSON object per line,
// a frame at a time, for a client with no zstd to hand. It returns how many
// bytes it wrote, so a caller can tell a failure before the response began
// from one that cut it short.
func (d *Download) WriteNDJSON(ctx context.Context, w io.Writer) (int64, error) {
	var written int64
	for i := range d.file.frames {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		raw, err := d.file.decodeFrame(i)
		if err != nil {
			return written, err
		}
		n, err := w.Write(raw)
		written += int64(n)
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// Close releases the file and its slot.
func (d *Download) Close() error {
	err := d.file.Close()
	d.release.Do(func() { <-downloadSlots })
	return err
}

// Status describes the archive for the dashboard.
type Status struct {
	Settings         Settings
	TraceStoreActive bool
	Segments         int
	TotalBytes       int64
	// Oldest and Newest are the starts of the oldest and newest archived
	// hours; zero when there are none.
	Oldest, Newest time.Time
	LastWritten    time.Time
	LastError      string
	LastErrorAt    time.Time
}

// Status reports the archive as of the archiver's last look at it.
func (a *Archiver) Status() Status {
	st := a.snapshot()
	s := Status{
		Settings:         CurrentSettings(),
		TraceStoreActive: telemetry.TraceStoreActive(),
		Segments:         st.stats.segments,
		TotalBytes:       st.stats.bytes,
		LastWritten:      st.lastWritten,
		LastError:        st.lastErr,
		LastErrorAt:      st.lastErrAt,
	}
	if st.stats.segments > 0 {
		s.Oldest, s.Newest = st.stats.oldest.start, st.stats.newest.start
	}
	return s
}
