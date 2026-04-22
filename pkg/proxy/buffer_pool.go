package proxy

import (
	"sync"
)

var bufferPool = &syncBufferPool{
	pool: sync.Pool{
		New: func() any {
			return make([]byte, 32*1024)
		},
	},
}

type syncBufferPool struct {
	pool sync.Pool
}

func (p *syncBufferPool) Get() []byte {
	b := p.pool.Get()
	if b == nil {
		return make([]byte, 32*1024)
	}
	return b.([]byte)
}

func (p *syncBufferPool) Put(b []byte) {
	p.pool.Put(b)
}
