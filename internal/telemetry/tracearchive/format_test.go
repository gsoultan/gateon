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
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

// bigLines writes n traces of about size bytes each into a fresh segment and
// returns the segment's path and its NDJSON as it should decompress.
func bigLines(t *testing.T, root string, seg Segment, n, size int) (string, []byte) {
	t.Helper()
	w, err := newSegmentWriter(root, seg)
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	for i := range n {
		at := seg.Start().Add(time.Duration(i) * time.Second)
		l := fmt.Appendf(nil, `{"id":"t%04d","timestamp":%q,"path":"/%s"}`, i, at.Format(time.RFC3339Nano), strings.Repeat("x", size))
		w.fromStore(false)
		if err := w.add(l, at.UnixNano()); err != nil {
			t.Fatal(err)
		}
		want.Write(l)
		want.WriteByte('\n')
	}
	if _, published, err := w.commit(); err != nil || !published {
		t.Fatalf("commit: published=%v err=%v", published, err)
	}
	return seg.path(root), want.Bytes()
}

// A segment has to be several frames for the index to mean anything, and every
// frame must read back in order, forwards and backwards.
func TestSegment_RoundTripsAcrossFrames(t *testing.T) {
	root := t.TempDir()
	seg := hour(t, "2026-09-26T14")
	path, want := bigLines(t, root, seg, 300, 8<<10)

	f, err := openSegment(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if len(f.frames) < 2 {
		t.Fatalf("%d frames; the test needs several to exercise the index", len(f.frames))
	}
	if f.meta.Count != 300 || f.meta.Stored != 300 || f.meta.RawBytes != int64(len(want)) {
		t.Fatalf("header = %+v, want 300 traces of %d bytes", f.meta, len(want))
	}

	var forward, backward [][]byte
	ctx := context.Background()
	all := nanoWindow{lo: minNanos, hi: maxNanos}
	if _, err := f.scan(ctx, all, func(l []byte) bool { forward = append(forward, bytes.Clone(l)); return true }); err != nil {
		t.Fatal(err)
	}
	all.desc = true
	if _, err := f.scan(ctx, all, func(l []byte) bool { backward = append(backward, bytes.Clone(l)); return true }); err != nil {
		t.Fatal(err)
	}
	if got := append(bytes.Join(forward, []byte("\n")), '\n'); !bytes.Equal(got, want) {
		t.Fatal("forward scan does not reproduce the traces written")
	}
	slices.Reverse(backward)
	if !slices.EqualFunc(forward, backward, bytes.Equal) {
		t.Fatal("backward scan is not the forward scan reversed")
	}
}

// The header and the index are skippable frames, so a stock zstd decoder
// reads a segment as plain NDJSON: that is the promise `zstd -dc` relies on.
func TestSegment_IsPlainNDJSONToAnyZstdDecoder(t *testing.T) {
	root := t.TempDir()
	path, want := bigLines(t, root, hour(t, "2026-09-26T15"), 200, 8<<10)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := zstd.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	got, err := io.ReadAll(dec)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("streaming decode: %d bytes, err %v; want the %d bytes written", len(got), err, len(want))
	}

	cli, err := exec.LookPath("zstd")
	if err != nil {
		t.Log("zstd not installed; the command-line check is skipped")
		return
	}
	out, err := exec.Command(cli, "-dc", path).Output() // #nosec G204 -- a test's own temp file
	if err != nil || !bytes.Equal(out, want) {
		t.Fatalf("zstd -dc: %d bytes, err %v; want the %d bytes written", len(out), err, len(want))
	}
}

// Decoding only the frames that can hold a window is the point of the index.
func TestFrameRange_PicksOnlyTheFramesAWindowNeeds(t *testing.T) {
	root := t.TempDir()
	seg := hour(t, "2026-09-26T16")
	path, _ := bigLines(t, root, seg, 300, 8<<10)
	f, err := openSegment(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	mid := f.frames[len(f.frames)/2]
	a, b := f.frameRange(mid.first, mid.first+1)
	if b-a != 1 || f.frames[a] != mid {
		t.Fatalf("a window inside one frame decoded frames [%d, %d) of %d", a, b, len(f.frames))
	}
	if a, b := f.frameRange(seg.End().UnixNano(), maxNanos); a != b {
		t.Fatalf("a window after the hour picked frames [%d, %d)", a, b)
	}
}

func TestCommit_WithNoTracesPublishesNothing(t *testing.T) {
	root := t.TempDir()
	seg := hour(t, "2026-09-26T17")
	w, err := newSegmentWriter(root, seg)
	if err != nil {
		t.Fatal(err)
	}
	if _, published, err := w.commit(); err != nil || published {
		t.Fatalf("commit = published %v, err %v; want nothing published", published, err)
	}
	left, _ := os.ReadDir(filepath.Join(root, seg.dir()))
	if len(left) != 0 {
		t.Fatalf("left %d file(s) behind: %v", len(left), left)
	}
}

// A damaged file must be refused, not read as far as it goes: a truncated
// segment that reads as complete is how a hole in history goes unnoticed.
func TestOpenSegment_RefusesDamage(t *testing.T) {
	root := t.TempDir()
	seg := hour(t, "2026-09-26T18")
	path, _ := bigLines(t, root, seg, 50, 1<<10)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]byte) []byte{
		"truncated":         func(b []byte) []byte { return b[:len(b)-7] },
		"header only":       func(b []byte) []byte { return b[:headerSize] },
		"header scrambled":  func(b []byte) []byte { b[20] ^= 0xff; return b },
		"not a segment":     func([]byte) []byte { return []byte("{\"id\":\"x\"}\n") },
		"wrong frame magic": func(b []byte) []byte { b[0] = 0; return b },
	}
	// Every byte of the index, one bit at a time: an offset or a time that
	// changes by one is as wrong as one that changes by a lot.
	indexAt := len(good) - (skippableHeaderLen + indexEntrySize*len(indexOf(t, path)))
	for i := indexAt; i < len(good); i++ {
		cases[fmt.Sprintf("index byte %d", i-indexAt)] = func(b []byte) []byte { b[i] ^= 0x01; return b }
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, damage(bytes.Clone(good)), 0o600); err != nil {
				t.Fatal(err)
			}
			if f, err := openSegment(path); err == nil {
				f.Close()
				t.Fatal("a damaged segment opened cleanly")
			} else if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error = %v, want ErrCorrupt", err)
			}
		})
	}
}

func indexOf(t *testing.T, path string) []frameEntry {
	t.Helper()
	f, err := openSegment(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return f.frames
}
