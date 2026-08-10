// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"sync"
	"unsafe"
)

type buffer [32 * 1024]byte

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

func (p *syncBufferPool) Put(b []byte) {
	if cap(b) < 32*1024 {
		return
	}
	p.pool.Put((*buffer)(unsafe.Pointer(&b[0])))
}
