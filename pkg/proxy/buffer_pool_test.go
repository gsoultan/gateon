// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import "testing"

// Put used to do unsafe.Pointer(&b[0]). Indexing element zero panics on a
// zero-length slice regardless of its capacity, so handing back a buffer that
// had been fully consumed — the ordinary b[:0] idiom — killed the goroutine
// doing the proxying. The capacity guard above it did not help, because
// capacity is not what &b[0] requires.
//
// Against the pre-fix code the zero-length case panics with
// "index out of range [0] with length 0".
func TestBufferPoolPutAcceptsAnyLengthWithinCapacity(t *testing.T) {
	full := make([]byte, bufferSize)

	tests := []struct {
		name string
		buf  []byte
	}{
		{name: "full length", buf: full},
		{name: "zero length, full capacity", buf: full[:0]},
		{name: "partial length", buf: full[:1024]},
		{name: "one byte", buf: full[:1]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Put panicked on a %d-length buffer with capacity %d: %v",
						len(tt.buf), cap(tt.buf), r)
				}
			}()
			bufferPool.Put(tt.buf)
		})
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
	bufferPool.Put(make([]byte, 128))
	bufferPool.Put(nil)
	bufferPool.Put([]byte{})
}

// Get must always return a buffer of exactly bufferSize, including after a
// short-but-within-capacity buffer has been returned to the pool.
func TestBufferPoolGetIsAlwaysFullSize(t *testing.T) {
	full := make([]byte, bufferSize)
	bufferPool.Put(full[:0])

	for i := range 4 {
		got := bufferPool.Get()
		if len(got) != bufferSize {
			t.Fatalf("iteration %d: Get() len = %d, want %d", i, len(got), bufferSize)
		}
		bufferPool.Put(got)
	}
}

func BenchmarkBufferPoolGetPut(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		buf := bufferPool.Get()
		bufferPool.Put(buf)
	}
}
