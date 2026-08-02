// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package phantom

import (
	"context"
	"net"
	"net/http"
)

// PhantomCore defines the interface for the high-performance TITAN proxy core.
type PhantomCore interface {
	// ProxyL4 handles zero-copy L4 proxying using AF_XDP on Linux.
	// targetAddr is the address to proxy to.
	ProxyL4(ctx context.Context, client net.Conn, targetAddr string) error

	// ServeHTTP leverages io_uring for high-performance L7 request handling.
	// It wraps a standard http.Handler to provide kernel-bypass optimized ingress.
	ServeHTTP(ctx context.Context, listener net.Listener, handler http.Handler) error
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
