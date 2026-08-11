// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build !linux

package phantom

import (
	"context"
	"github.com/gsoultan/gateon/pkg/l4"
	"io"
	"net"
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
	defer backend.Close()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := l4.SpliceCopy(backend, client); err != nil {
			_, _ = io.Copy(backend, client)
		}
	}()
	if _, err := l4.SpliceCopy(client, backend); err != nil {
		_, _ = io.Copy(client, backend)
	}
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
