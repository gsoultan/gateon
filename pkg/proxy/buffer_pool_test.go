// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import "testing"

// shapeTestPool is the pool the Put-shape tests below put into: a private one,
// never the shared bufferPool. They put one array several times over, and in
// the shared pool that left several references to it, so the next callers --
// an upgrade tunnel's two copy directions -- were handed the same 32 KiB and
// both read into it: TestATunnelEndsAtItsMaxLifetime reported a DATA RACE
// under -race whenever a shuffle ran this file first (seed 1790993191911123000).
func shapeTestPool() *syncBufferPool { return newBufferPool() }

// putEveryShape puts one full-capacity array into p at every length the Put
// tests cover.
func putEveryShape(t *testing.T, p *syncBufferPool) {
	t.Helper()
	full := make([]byte, bufferSize)
	for _, b := range [][]byte{full, full[:0], full[:1024], full[:1]} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Put panicked on a %d-length buffer with capacity %d: %v", len(b), cap(b), r)
				}
			}()
			p.Put(b)
		}()
	}
}

// Put used to do unsafe.Pointer(&b[0]). Indexing element zero panics on a
// zero-length slice regardless of its capacity, so handing back a buffer that
// had been fully consumed — the ordinary b[:0] idiom — killed the goroutine
// doing the proxying. The capacity guard above it did not help, because
// capacity is not what &b[0] requires.
//
// Against the pre-fix code the zero-length case panics with
// "index out of range [0] with length 0".
func TestBufferPoolPutAcceptsAnyLengthWithinCapacity(t *testing.T) {
	putEveryShape(t, shapeTestPool())
}

// TestThePoolTestsLeaveTheSharedPoolAlone: after the Put-shape test's puts, two
// holders of the shared pool -- a tunnel's two directions -- get two buffers.
// Repeated so that sync.Pool's random drops under -race cannot hide a shared
// one. Against the old test, which put into bufferPool, the two Gets returned
// the same array.
func TestThePoolTestsLeaveTheSharedPoolAlone(t *testing.T) {
	for range 8 {
		putEveryShape(t, shapeTestPool())
		a, b := bufferPool.Get(), bufferPool.Get()
		same := &a[0] == &b[0]
		bufferPool.Put(a)
		if !same {
			bufferPool.Put(b)
		}
		if same {
			t.Fatal("the shared pool handed one buffer to two holders: a test put the same array into it more than once")
		}
	}
}

// Undersized buffers must be dropped: Get hands out a full-size slice, so
// storing a short one would silently shrink every later copy.
func TestBufferPoolPutRejectsUndersized(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Put panicked on an undersized buffer: %v", r)
		}
	}()
	p := shapeTestPool()
	p.Put(make([]byte, 128))
	p.Put(nil)
	p.Put([]byte{})
}

// Get must always return a buffer of exactly bufferSize, including after a
// short-but-within-capacity buffer has been returned to the pool.
func TestBufferPoolGetIsAlwaysFullSize(t *testing.T) {
	p := shapeTestPool()
	full := make([]byte, bufferSize)
	p.Put(full[:0])

	for i := range 4 {
		got := p.Get()
		if len(got) != bufferSize {
			t.Fatalf("iteration %d: Get() len = %d, want %d", i, len(got), bufferSize)
		}
		p.Put(got)
	}
}

func BenchmarkBufferPoolGetPut(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		buf := bufferPool.Get()
		bufferPool.Put(buf)
	}
}
