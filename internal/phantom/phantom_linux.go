// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

//go:build linux

package phantom

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"

	"github.com/asavie/xdp"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/pkg/l4"
	"github.com/iceber/iouring-go"
)

// linuxCore is the hardware-accelerated TITAN core for Linux systems.
type linuxCore struct {
	ring *iouring.IOURing
	ebpf EbpfManager
	mu   sync.RWMutex
}

// newPhantomCore returns the Linux-specific TITAN core implementation.
func newPhantomCore(ebpf EbpfManager) PhantomCore {
	// Attempt to initialize io_uring with a large enough queue size.
	// io_uring is used to optimize ingress HTTP handling.
	ring, err := iouring.New(8192)
	if err != nil {
		logger.L.LogWarn("io_uring initialization failed, falling back to standard I/O", "error", err)
		return &linuxCore{ebpf: ebpf}
	}
	return &linuxCore{ring: ring, ebpf: ebpf}
}

// ProxyL4 implements high-performance L4 proxying.
// It attempts to use AF_XDP if configured and possible, otherwise falls back to splice(2).
func (c *linuxCore) ProxyL4(ctx context.Context, client net.Conn, targetAddr string) error {
	// Check for AF_XDP optimization availability.
	// AF_XDP requires an interface to attach to.
	ifaceName := os.Getenv("GATEON_XDP_IFACE")
	if ifaceName != "" {
		if err := c.proxyWithXDP(ctx, client, targetAddr, ifaceName); err == nil {
			return nil
		}
		logger.L.LogWarn("AF_XDP proxying failed or unavailable, falling back to splice", "interface", ifaceName)
	}

	// High-performance fallback: kernel-level splicing.
	return c.proxyWithSplice(ctx, client, targetAddr)
}

func (c *linuxCore) proxyWithSplice(ctx context.Context, client net.Conn, targetAddr string) error {
	dialer := net.Dialer{}
	backend, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		client.Close()
		return err
	}
	defer backend.Close()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Splice from backend to client
		if _, err := l4.SpliceCopy(client, backend); err != nil {
			_, _ = io.Copy(client, backend)
		}
	}()

	// Splice from client to backend
	if _, err := l4.SpliceCopy(backend, client); err != nil {
		_, _ = io.Copy(backend, client)
	}
	<-done
	return nil
}

func (c *linuxCore) proxyWithXDP(ctx context.Context, client net.Conn, targetAddr string, ifaceName string) error {
	// AF_XDP implementation using github.com/asavie/xdp.
	// TITAN implementation: We register the port in eBPF and use AF_XDP to bypass the kernel.
	
	// Get destination port from targetAddr
	_, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	var port uint32
	fmt.Sscanf(portStr, "%d", &port)

	// Register port in eBPF for redirection
	if c.ebpf != nil {
		_ = c.ebpf.RegisterPhantomPort(port)
		defer c.ebpf.UnregisterPhantomPort(port)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	
	// AF_XDP Socket creation
	xsk, err := xdp.NewSocket(iface.Index, 0, nil)
	if err != nil {
		return fmt.Errorf("AF_XDP socket creation failed: %w", err)
	}
	defer xsk.Close()

	// In a production TITAN implementation, we would now perform zero-copy 
	// packet forwarding between the XDP socket and the backend.
	// For now, we signal readiness and perform a high-performance fallback 
	// while the AF_XDP userspace loop is being finalized.
	return fmt.Errorf("AF_XDP packet loop requires userspace TCP stack integration")
}

// ServeHTTP leverages io_uring to provide high-performance L7 ingress.
func (c *linuxCore) ServeHTTP(ctx context.Context, listener net.Listener, handler http.Handler) error {
	server := &http.Server{
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
	}()

	// If io_uring is available, we wrap the listener to optimize Accept calls.
	if c.ring != nil {
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			return server.Serve(&iouringListener{
				TCPListener: tcpListener,
				ring:        c.ring,
			})
		}
	}

	return server.Serve(listener)
}

// iouringListener wraps a TCPListener to use io_uring for accepts.
type iouringListener struct {
	*net.TCPListener
	ring *iouring.IOURing
}

func (l *iouringListener) Accept() (net.Conn, error) {
	// Obtain the underlying file descriptor for the listener.
	rawConn, err := l.TCPListener.SyscallConn()
	if err != nil {
		return l.TCPListener.Accept()
	}

	var fd int
	err = rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return l.TCPListener.Accept()
	}

	// Use io_uring to accept the next connection.
	ch := make(chan iouring.Result, 1)
	prepReq := iouring.Accept(fd)
	if _, err := l.ring.SubmitRequest(prepReq, ch); err != nil {
		return l.TCPListener.Accept()
	}

	result := <-ch
	if result.Err() != nil {
		return nil, result.Err()
	}

	newFd, err := result.ReturnFd()
	if err != nil {
		return nil, err
	}

	// Convert the file descriptor back to a net.Conn.
	file := os.NewFile(uintptr(newFd), "iouring-accept")
	conn, err := net.FileConn(file)
	file.Close() // net.FileConn dups the fd, so we can close our copy
	if err != nil {
		return nil, err
	}

	// Get the actual FD used by the new connection for io_uring operations.
	var actualFd int
	if sc, ok := conn.(syscall.Conn); ok {
		if rc, err := sc.SyscallConn(); err == nil {
			_ = rc.Control(func(f uintptr) {
				actualFd = int(f)
			})
		}
	}

	if actualFd == 0 {
		actualFd = newFd // Fallback if SyscallConn failed
	}

	return &iouringConn{
		Conn: conn,
		ring: l.ring,
		fd:   actualFd,
	}, nil
}

// iouringConn wraps a net.Conn to use io_uring for Read and Write.
type iouringConn struct {
	net.Conn
	ring *iouring.IOURing
	fd   int
}

func (c *iouringConn) Read(b []byte) (n int, err error) {
	ch := make(chan iouring.Result, 1)
	prepReq := iouring.Read(c.fd, b)
	if _, err := c.ring.SubmitRequest(prepReq, ch); err != nil {
		return c.Conn.Read(b)
	}
	res := <-ch
	if res.Err() != nil {
		return 0, res.Err()
	}
	n, err = res.ReturnInt()
	return n, err
}

func (c *iouringConn) Write(b []byte) (n int, err error) {
	// Optimization: For larger buffers, we could use Writev.
	// We demonstrate Writev usage here for data > 4KB.
	if len(b) > 4096 {
		return c.writev(b)
	}

	ch := make(chan iouring.Result, 1)
	prepReq := iouring.Write(c.fd, b)
	if _, err := c.ring.SubmitRequest(prepReq, ch); err != nil {
		return c.Conn.Write(b)
	}
	res := <-ch
	if res.Err() != nil {
		return 0, res.Err()
	}
	n, err = res.ReturnInt()
	return n, err
}

func (c *iouringConn) writev(b []byte) (int, error) {
	// Split buffer into two vectors for writev demonstration.
	mid := len(b) / 2
	bs := [][]byte{b[:mid], b[mid:]}

	ch := make(chan iouring.Result, 1)
	prepReq := iouring.Writev(c.fd, bs)
	if _, err := c.ring.SubmitRequest(prepReq, ch); err != nil {
		return c.Conn.Write(b)
	}
	res := <-ch
	if res.Err() != nil {
		return 0, res.Err()
	}
	return res.ReturnInt()
}
