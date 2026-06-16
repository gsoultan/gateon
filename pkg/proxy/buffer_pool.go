package proxy

import (
	"sync"
)

var bufferPool = &syncBufferPool{
	pool: sync.Pool{
		New: func() any {
			b := make([]byte, 32*1024)
			return &b
		},
	},
}

type syncBufferPool struct {
	pool sync.Pool
}

func (p *syncBufferPool) Get() []byte {
	bp, ok := p.pool.Get().(*[]byte)
	if !ok || bp == nil {
		return make([]byte, 32*1024)
	}
	return *bp
}

func (p *syncBufferPool) Put(b []byte) {
	p.pool.Put(&b)
}
