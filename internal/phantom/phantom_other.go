// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build !linux

package phantom

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/gsoultan/gateon/pkg/l4"
)

type fallbackCore struct{}

func newPhantomCore(ebpf EbpfManager) PhantomCore {
	return &fallbackCore{}
}

func (c *fallbackCore) ProxyL4(ctx context.Context, client net.Conn, targetAddr string) error {
	dialer := net.Dialer{}
	backend, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		_ = client.Close()
		return err
	}
	// Whichever direction finishes first closes both sides.
	//
	// Without this the two copies were waited on together while neither could
	// end the other: the caller's copy returns when its source stops, and the
	// wait on `done` then blocks on a copy whose source is simply idle. A client
	// that disconnects while the backend holds its side open -- any protocol
	// where the server speaks only when spoken to -- left that second copy
	// blocked forever, and the Close calls were deferred behind the wait for it.
	// One goroutine and two sockets per disconnected client, held for the life of
	// the process, on the path whose whole purpose is connection volume.
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			_ = client.Close()
			_ = backend.Close()
		})
	}
	defer shutdown()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer shutdown()
		if _, err := l4.SpliceCopy(backend, client); err != nil {
			_, _ = io.Copy(backend, client)
		}
	}()
	if _, err := l4.SpliceCopy(client, backend); err != nil {
		_, _ = io.Copy(client, backend)
	}
	shutdown()
	<-done
	return nil
}

func (c *fallbackCore) OptimizeListener(l net.Listener) net.Listener {
	return l
}

func (c *fallbackCore) GetStatus() (enabled bool, engine string, activePorts int) {
	return false, "standard (no-linux fallback)", 0
}

func (c *fallbackCore) Close() error {
	return nil
}
