// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"sync"
)

// bufferSize is the copy buffer handed to io.CopyBuffer on the proxy path. It
// matches httputil.ReverseProxy's own default.
const bufferSize = 32 * 1024

type buffer [bufferSize]byte

var bufferPool = &syncBufferPool{
	pool: sync.Pool{
		New: func() any {
			return new(buffer)
		},
	},
}

type syncBufferPool struct {
	pool sync.Pool
}

func (p *syncBufferPool) Get() []byte {
	return p.pool.Get().(*buffer)[:]
}

// Put returns a buffer to the pool. Buffers smaller than bufferSize are dropped
// rather than stored, because Get hands out a full-size slice and a short one
// would silently shrink every subsequent copy.
//
// The conversion is the language's checked slice-to-array-pointer form, not
// unsafe.Pointer. The previous version took unsafe.Pointer(&b[0]), which
// indexes element zero — and that panics on a zero-length slice even when its
// capacity is ample, so returning a fully consumed buffer as b[:0] took down
// the proxy goroutine. Re-slicing to bufferSize first satisfies the conversion's
// length requirement no matter what len the caller had left.
func (p *syncBufferPool) Put(b []byte) {
	if cap(b) < bufferSize {
		return
	}
	p.pool.Put((*buffer)(b[:bufferSize]))
}
