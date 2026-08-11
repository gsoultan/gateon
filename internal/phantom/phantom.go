// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package phantom

import (
	"context"
	"net"
)

// PhantomCore defines the interface for the high-performance TITAN proxy core.
type PhantomCore interface {
	// ProxyL4 handles zero-copy L4 proxying using AF_XDP on Linux.
	// targetAddr is the address to proxy to.
	ProxyL4(ctx context.Context, client net.Conn, targetAddr string) error

	// OptimizeListener wraps the given listener with high-performance TITAN optimizations
	// (e.g. io_uring for Accept, Read, and Write).
	OptimizeListener(l net.Listener) net.Listener

	// GetStatus returns the current operational status of the Phantom core.
	GetStatus() (enabled bool, engine string, activePorts int)

	// Close releases all TITAN-specific resources (e.g. io_uring rings, AF_XDP sockets).
	Close() error
}

// EbpfManager defines the subset of eBPF operations required by the Phantom core.
type EbpfManager interface {
	RegisterPhantomPort(port uint32) error
	UnregisterPhantomPort(port uint32) error
}

// NewPhantomCore returns a production-ready TITAN core.
// On Linux, it returns the hardware-accelerated implementation.
// On other platforms, it returns a high-performance fallback based on standard libraries.
func NewPhantomCore(ebpf EbpfManager) PhantomCore {
	return newPhantomCore(ebpf)
}
