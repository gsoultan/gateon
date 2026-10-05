// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"cmp"
	"encoding/binary"
	"net/netip"
	"slices"
)

// The feed index is a sorted list of address ranges per family, merged so no
// two overlap or touch (ADR 0061). It replaced a binary trie with a node per
// prefix bit and a map from every host entry's text to its score: a million
// IPv4 addresses held ~500 MiB in those and took ~1 GiB to rebuild, and a
// million IPv6 ones -- a hundred-odd trie nodes each -- ran the 2 GB host out
// of memory. Every feed entry carries the same score (feedListedScore), so
// "is this address covered" is all the index has to answer, and a range
// answers it in 8 bytes for IPv4 and 32 for IPv6, with a binary search.

// v4Range is the IPv4 addresses lo..hi, inclusive.
type v4Range struct{ lo, hi uint32 }

// u128 is an IPv6 address as a number.
type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo) }

func (a u128) or(b u128) u128 { return u128{a.hi | b.hi, a.lo | b.lo} }

// next is a+1; ok is false when a is the last address.
func (a u128) next() (u128, bool) {
	if a.lo != ^uint64(0) {
		return u128{a.hi, a.lo + 1}, true
	}
	if a.hi != ^uint64(0) {
		return u128{a.hi + 1, 0}, true
	}
	return a, false
}

func u128Of(a netip.Addr) u128 {
	b := a.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

// hostMask has the low hostBits bits set.
func hostMask(hostBits int) u128 {
	switch {
	case hostBits >= 128:
		return u128{^uint64(0), ^uint64(0)}
	case hostBits >= 64:
		return u128{1<<(hostBits-64) - 1, ^uint64(0)}
	default:
		return u128{0, 1<<hostBits - 1}
	}
}

// v6Range is the IPv6 addresses lo..hi, inclusive.
type v6Range struct{ lo, hi u128 }

// Bytes one range takes in the index: what the byte bound counts.
const (
	v4RangeBytes = 8
	v6RangeBytes = 32
)

// entryBytes is what an entry for p costs in the index.
func entryBytes(p netip.Prefix) int64 {
	if p.Addr().Is4() {
		return v4RangeBytes
	}
	return v6RangeBytes
}

// feedRanges is a set of prefixes as sorted, merged ranges. Once built it is
// never modified, so an index and a feed's last good copy may share one.
type feedRanges struct {
	v4 []v4Range
	v6 []v6Range
	// v4Top and v6Top narrow a lookup to the ranges that start under the
	// address's top 16 bits: entry k is the index of the first range whose
	// start's top 16 bits are k or more. A binary search over a million
	// ranges is twenty dependent reads across 8 MiB; this makes it two reads
	// and a search over the dozen or so ranges of one bucket. Nil for a
	// family with fewer than topIndexMin ranges, where the search is short.
	v4Top, v6Top []uint32
}

// topIndexMin is how many ranges a family needs for a top index, which
// costs a fixed 256 KiB.
const topIndexMin = 1024

// topBuckets is the number of top-16-bit buckets.
const topBuckets = 1 << 16

// buildTop is the top index of n ranges whose starts' top 16 bits top16
// gives, in order; nil below topIndexMin.
func buildTop(n int, top16 func(i int) uint32) []uint32 {
	if n < topIndexMin {
		return nil
	}
	t := make([]uint32, topBuckets+1)
	k := 0
	for i := range n {
		for b := int(top16(i)); k <= b; k++ {
			t[k] = uint32(i)
		}
	}
	for ; k <= topBuckets; k++ {
		t[k] = uint32(n)
	}
	return t
}

// topIndexBytes is what the two top indexes of an index can take at most;
// the byte bound reserves it.
const topIndexBytes = 2 * (topBuckets + 1) * 4

func topV4(r []v4Range) []uint32 {
	return buildTop(len(r), func(i int) uint32 { return r[i].lo >> 16 })
}

func topV6(r []v6Range) []uint32 {
	return buildTop(len(r), func(i int) uint32 { return uint32(r[i].lo.hi >> 48) })
}

// bucketOf is the slice of ranges [lo, hi) a lookup of an address whose top
// 16 bits are k needs to search, given top (nil: all n).
func bucketOf(top []uint32, k uint32, n int) (lo, hi int) {
	if top == nil {
		return 0, n
	}
	return int(top[k]), int(top[k+1])
}

// rangeBuilder collects ranges in fixed-size chunks, so a feed of unknown
// length is read without the geometric over-allocation of a growing slice --
// about five times the final size, summed over the grows -- and copied once,
// into an exact-size slice, when it is complete.
type rangeBuilder struct {
	v4 [][]v4Range
	v6 [][]v6Range
}

// rangeChunk is the number of ranges in one chunk: 64 KiB of IPv4 ranges.
const rangeChunk = 8192

// appendChunked appends x to the last chunk, starting a new one when it is
// full.
func appendChunked[T any](chunks [][]T, x T) [][]T {
	if n := len(chunks); n == 0 || len(chunks[n-1]) == cap(chunks[n-1]) {
		chunks = append(chunks, make([]T, 0, rangeChunk))
	}
	last := len(chunks) - 1
	chunks[last] = append(chunks[last], x)
	return chunks
}

// flatten copies the chunks into one exact-size slice.
func flatten[T any](chunks [][]T) []T {
	n := 0
	for _, c := range chunks {
		n += len(c)
	}
	if n == 0 {
		return nil
	}
	out := make([]T, 0, n)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

// add records p's range.
func (b *rangeBuilder) add(p netip.Prefix) {
	p = p.Masked()
	if p.Addr().Is4() {
		a := p.Addr().As4()
		lo := binary.BigEndian.Uint32(a[:])
		hi := lo | uint32(uint64(1)<<(32-p.Bits())-1)
		b.v4 = appendChunked(b.v4, v4Range{lo, hi})
		return
	}
	lo := u128Of(p.Addr())
	b.v6 = appendChunked(b.v6, v6Range{lo, lo.or(hostMask(128 - p.Bits()))})
}

// ranges is what was added, sorted and merged.
func (b *rangeBuilder) ranges() feedRanges {
	return feedRanges{v4: mergeV4(flatten(b.v4)), v6: mergeV6(flatten(b.v6))}
}

// bytes is what the ranges and their top indexes take in memory.
func (f *feedRanges) bytes() int64 {
	return int64(cap(f.v4))*v4RangeBytes + int64(cap(f.v6))*v6RangeBytes + 4*int64(cap(f.v4Top)+cap(f.v6Top))
}

func mergeV4(r []v4Range) []v4Range {
	if len(r) == 0 {
		return nil
	}
	slices.SortFunc(r, func(a, b v4Range) int { return cmp.Compare(a.lo, b.lo) })
	out := r[:1]
	for _, x := range r[1:] {
		last := &out[len(out)-1]
		if uint64(x.lo) <= uint64(last.hi)+1 {
			last.hi = max(last.hi, x.hi)
			continue
		}
		out = append(out, x)
	}
	return clipSlack(out)
}

func mergeV6(r []v6Range) []v6Range {
	if len(r) == 0 {
		return nil
	}
	slices.SortFunc(r, func(a, b v6Range) int {
		switch {
		case a.lo.less(b.lo):
			return -1
		case b.lo.less(a.lo):
			return 1
		}
		return 0
	})
	out := r[:1]
	for _, x := range r[1:] {
		last := &out[len(out)-1]
		// The address after last's range; at the top of the space next
		// cannot step and returns the last address, which x overlaps.
		if after, _ := last.hi.next(); !after.less(x.lo) {
			if last.hi.less(x.hi) {
				last.hi = x.hi
			}
			continue
		}
		out = append(out, x)
	}
	return clipSlack(out)
}

// clipSlack copies s to an exact-size slice when append or merging left any
// of it unused, so what the index holds is what the byte bound counted: the
// grown slice is garbage as soon as the copy is made.
func clipSlack[T any](s []T) []T {
	if cap(s) == len(s) {
		return s
	}
	out := make([]T, len(s))
	copy(out, s)
	return out
}

// containsV4 reports whether x falls in one of r's ranges. Every range before
// x's bucket starts below x and every one after it above x, so the last range
// starting at or below x is found by searching the bucket alone -- and may be
// the one just before it.
func containsV4(r []v4Range, top []uint32, x uint32) bool {
	lo, hi := bucketOf(top, x>>16, len(r))
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if r[mid].lo <= x {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo > 0 && r[lo-1].hi >= x
}

// containsV6 reports whether x falls in one of r's ranges; see containsV4.
func containsV6(r []v6Range, top []uint32, x u128) bool {
	lo, hi := bucketOf(top, uint32(x.hi>>48), len(r))
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if !x.less(r[mid].lo) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo > 0 && !r[lo-1].hi.less(x)
}

// contains reports whether addr, unmapped, is in the ranges.
func (f *feedRanges) contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		return containsV4(f.v4, f.v4Top, binary.BigEndian.Uint32(b[:]))
	}
	return containsV6(f.v6, f.v6Top, u128Of(addr))
}

// unionRanges is the merged union of every feed's ranges, with its top
// indexes. One feed's ranges are used as they are, shared with its last good
// copy, so a single feed is held once rather than twice.
func unionRanges(feeds []feedRanges) feedRanges {
	var v4s [][]v4Range
	var v6s [][]v6Range
	for _, f := range feeds {
		if len(f.v4) > 0 {
			v4s = append(v4s, f.v4)
		}
		if len(f.v6) > 0 {
			v6s = append(v6s, f.v6)
		}
	}
	u := feedRanges{v4: unionOf(v4s, mergeV4), v6: unionOf(v6s, mergeV6)}
	u.v4Top, u.v6Top = topV4(u.v4), topV6(u.v6)
	return u
}

// unionOf merges sets of ranges: the one set itself when there is one, else
// all of them concatenated into an exact-size slice and merged.
func unionOf[T any](sets [][]T, merge func([]T) []T) []T {
	switch len(sets) {
	case 0:
		return nil
	case 1:
		return sets[0]
	}
	n := 0
	for _, s := range sets {
		n += len(s)
	}
	all := make([]T, 0, n)
	for _, s := range sets {
		all = append(all, s...)
	}
	return merge(all)
}
