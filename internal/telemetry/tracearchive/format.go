// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"time"
)

// A segment file is a sequence of zstd frames:
//
//	header   skippable frame 0: JSON metadata, padded to a fixed size
//	data...  ordinary frames, each a run of whole NDJSON lines in key order
//	index    skippable frame 1: where each data frame starts, and its traces
//
// Every zstd decoder skips skippable frames, so `zstd -dc` of a segment is
// exactly its NDJSON. The header and index are what let the gateway read a
// segment without decompressing all of it: the header says what the file
// holds, and the index lets a reader decode only the frames covering the
// traces it wants, from either end.
const (
	formatName    = "gateon-traces"
	formatVersion = 1

	skippableMagic     = 0x184D2A50 // the low nibble is the skippable frame's ID
	skippableHeaderLen = 8          // magic and payload length, little-endian uint32s

	headerFrameID = 0
	indexFrameID  = 1

	// headerSize is the whole header frame. Its payload is padded to a fixed
	// size so a placeholder can be written first and the real header written
	// over it at the end, once the counts are known, without moving anything.
	headerSize        = 512
	headerPayloadSize = headerSize - skippableHeaderLen

	// indexEntrySize is one frameEntry: offset u64, length u32, count u32,
	// first i64, last i64.
	indexEntrySize = 32

	// frameTarget is how much NDJSON one data frame holds. A frame is what a
	// reader decodes at once, so this bounds the memory and the work behind a
	// page of results or a single trace lookup.
	frameTarget = 1 << 20
)

// ErrCorrupt is returned for a segment file whose header or index does not
// hold together.
var ErrCorrupt = errors.New("tracearchive: segment file is corrupt")

// segmentMeta is a segment's header. `head -c 512` of a segment shows it.
type segmentMeta struct {
	Format  string    `json:"format"`
	Version int       `json:"version"`
	Node    string    `json:"node"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	// Count is how many traces the file holds.
	Count int64 `json:"count"`
	// Stored is how many traces the store held for the hour when the file was
	// written, and Skipped how many of those could not be read and are not
	// here. The store gains traces for an hour after it closes -- a trace is
	// keyed by when its request started, so a long-lived connection lands in
	// an hour long past -- and a store holding a different number than Stored
	// is how the archiver knows to merge them in.
	Stored   int64     `json:"stored"`
	Skipped  int64     `json:"skipped,omitzero"`
	First    time.Time `json:"first,omitzero"`
	Last     time.Time `json:"last,omitzero"`
	RawBytes int64     `json:"rawBytes"`
	Frames   int       `json:"frames"`
	IndexAt  int64     `json:"indexAt"`
	// IndexCRC is the CRC-32 (IEEE) of the index frame. The data frames carry
	// zstd's own checksums; the index is not a zstd frame a decoder checks,
	// and a wrong offset or time in it sends a reader to the wrong traces.
	IndexCRC uint32    `json:"indexCrc"`
	Created  time.Time `json:"created"`
}

// frameEntry locates one data frame and brackets the traces in it.
type frameEntry struct {
	offset int64
	length uint32
	count  uint32
	first  int64 // UnixNano of the frame's first trace
	last   int64 // UnixNano of its last
}

func skippableHeader(id int, size int) []byte {
	h := binary.LittleEndian.AppendUint32(nil, skippableMagic|uint32(id))
	return binary.LittleEndian.AppendUint32(h, uint32(size))
}

// skippablePayload returns the payload of a skippable frame with the given ID
// that must fill b exactly.
func skippablePayload(b []byte, id int) ([]byte, error) {
	if len(b) < skippableHeaderLen || binary.LittleEndian.Uint32(b) != skippableMagic|uint32(id) {
		return nil, ErrCorrupt
	}
	if int64(binary.LittleEndian.Uint32(b[4:])) != int64(len(b)-skippableHeaderLen) {
		return nil, ErrCorrupt
	}
	return b[skippableHeaderLen:], nil
}

func encodeHeader(m segmentMeta) ([]byte, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(payload) > headerPayloadSize {
		return nil, fmt.Errorf("tracearchive: header of %d bytes does not fit in %d", len(payload), headerPayloadSize)
	}
	buf := append(skippableHeader(headerFrameID, headerPayloadSize), payload...)
	return append(buf, bytes.Repeat([]byte{' '}, headerSize-len(buf))...), nil
}

func decodeHeader(b []byte) (segmentMeta, error) {
	payload, err := skippablePayload(b, headerFrameID)
	if err != nil {
		return segmentMeta{}, err
	}
	var m segmentMeta
	if err := json.Unmarshal(bytes.TrimRight(payload, " "), &m); err != nil {
		return segmentMeta{}, ErrCorrupt
	}
	if m.Format != formatName || m.Version != formatVersion || m.IndexAt < headerSize {
		return segmentMeta{}, ErrCorrupt
	}
	return m, nil
}

func encodeIndex(frames []frameEntry) []byte {
	buf := skippableHeader(indexFrameID, len(frames)*indexEntrySize)
	for _, f := range frames {
		buf = binary.LittleEndian.AppendUint64(buf, uint64(f.offset))
		buf = binary.LittleEndian.AppendUint32(buf, f.length)
		buf = binary.LittleEndian.AppendUint32(buf, f.count)
		buf = binary.LittleEndian.AppendUint64(buf, uint64(f.first))
		buf = binary.LittleEndian.AppendUint64(buf, uint64(f.last))
	}
	return buf
}

// decodeIndex reads the index frame and checks it against the header: the
// frames must tile the file between the header and the index, in time order,
// and hold the number of traces the header says.
func decodeIndex(b []byte, m segmentMeta) ([]frameEntry, error) {
	if m.Frames < 0 || m.Frames > len(b)/indexEntrySize || crc32.ChecksumIEEE(b) != m.IndexCRC {
		return nil, ErrCorrupt
	}
	payload, err := skippablePayload(b, indexFrameID)
	if err != nil || len(payload) != m.Frames*indexEntrySize {
		return nil, ErrCorrupt
	}
	frames := make([]frameEntry, m.Frames)
	for i := range frames {
		e := payload[i*indexEntrySize:]
		frames[i] = frameEntry{
			offset: int64(binary.LittleEndian.Uint64(e)),
			length: binary.LittleEndian.Uint32(e[8:]),
			count:  binary.LittleEndian.Uint32(e[12:]),
			first:  int64(binary.LittleEndian.Uint64(e[16:])),
			last:   int64(binary.LittleEndian.Uint64(e[24:])),
		}
	}
	if !framesTile(frames, m) {
		return nil, ErrCorrupt
	}
	return frames, nil
}

func framesTile(frames []frameEntry, m segmentMeta) bool {
	at, count := int64(headerSize), int64(0)
	prevLast, lo, hi := m.Start.UnixNano(), m.Start.UnixNano(), m.End.UnixNano()
	for _, f := range frames {
		if f.offset != at || f.length == 0 || f.count == 0 || f.first < prevLast || f.first > f.last || f.last >= hi || f.first < lo {
			return false
		}
		at += int64(f.length)
		count += int64(f.count)
		prevLast = f.last
	}
	return at == m.IndexAt && count == m.Count
}
