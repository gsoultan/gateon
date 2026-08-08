// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

//go:build linux

package phantom

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/asavie/xdp"
	"github.com/godzie44/go-uring/reactor"
	"github.com/godzie44/go-uring/uring"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/pkg/l4"
)

// linuxCore is the hardware-accelerated TITAN core for Linux systems.
type linuxCore struct {
	ring        *uring.Ring
	rea         *reactor.Reactor
	ebpf        EbpfManager
	activePorts atomic.Int32
	ctx         context.Context
	cancel      context.CancelFunc
	// reactorDone is closed when the reactor goroutine has returned. Close
	// waits on it before freeing the ring: cancelling the context only asks the
	// reactor to stop, and unmapping the ring while it is still running is a
	// use-after-free.
	reactorDone chan struct{}
	mu          sync.RWMutex
}

// newPhantomCore returns the Linux-specific TITAN core implementation.
//
// The io_uring listener is opt-in via GATEON_PHANTOM=1. It was on by default
// and wrapped every listener on every Linux deployment, which cost more than it
// bought:
//
//   - A single accept error killed the listener. iouringListener.Accept
//     returned io_uring's error straight to http.Server.Serve, which treats a
//     non-temporary accept failure as fatal, so one EINVAL took down the whole
//     server. Observed in CI as `Management server failed: invalid argument`
//     on :8080 and again on :8085, after which every later test failed waiting
//     for a port that was no longer listening.
//   - Accepted connections came back as iouringConn rather than *net.TCPConn,
//     so a hijacked WebSocket did its reads and writes through io_uring. The
//     upgrade stalled: the gateway wrote nothing at all and the client sat
//     until its own deadline.
//
// Neither is inherent to io_uring, and the Accept path is hardened below. But
// an optimization with no benchmark behind it should not be the default when it
// can take the management plane offline, so it now has to be asked for.
func newPhantomCore(ebpf EbpfManager) PhantomCore {
	if os.Getenv("GATEON_PHANTOM") != "1" {
		return &linuxCore{ebpf: ebpf}
	}

	// Attempt to initialize io_uring with a large enough queue size.
	// io_uring is used to optimize ingress HTTP handling.
	ring, err := uring.New(8192)
	if err != nil {
		logger.L.LogWarn("io_uring initialization failed, falling back to standard I/O", "error", err)
		return &linuxCore{ebpf: ebpf}
	}

	rea, err := reactor.New([]*uring.Ring{ring})
	if err != nil {
		ring.Close()
		logger.L.LogWarn("io_uring reactor initialization failed, falling back to standard I/O", "error", err)
		return &linuxCore{ebpf: ebpf}
	}

	ctx, cancel := context.WithCancel(context.Background())
	reactorDone := make(chan struct{})
	go func() {
		defer close(reactorDone)
		rea.Run(ctx)
	}()

	return &linuxCore{
		ring:        ring,
		rea:         rea,
		ebpf:        ebpf,
		ctx:         ctx,
		cancel:      cancel,
		reactorDone: reactorDone,
	}
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
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return fmt.Errorf("invalid port in target address %s: %w", targetAddr, err)
	}

	// Register port in eBPF for redirection
	if c.ebpf != nil {
		_ = c.ebpf.RegisterPhantomPort(port)
		c.activePorts.Add(1)
		defer func() {
			_ = c.ebpf.UnregisterPhantomPort(port)
			c.activePorts.Add(-1)
		}()
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

// OptimizeListener wraps the given listener with io_uring optimizations.
func (c *linuxCore) OptimizeListener(l net.Listener) net.Listener {
	if c.ring != nil && c.rea != nil {
		if tcpListener, ok := l.(*net.TCPListener); ok {
			return &iouringListener{
				TCPListener: tcpListener,
				ring:        c.ring,
				rea:         c.rea,
				ctx:         c.ctx,
			}
		}
	}
	return l
}

// GetStatus returns the operational status of the Linux core.
func (c *linuxCore) GetStatus() (enabled bool, engine string, activePorts int) {
	if c.ring != nil {
		engine = "io_uring"
		enabled = true
	} else {
		engine = "standard"
	}

	if c.ebpf != nil {
		if engine != "" && engine != "standard" {
			engine += " + "
		}
		engine += "AF_XDP"
		enabled = true
	}

	activePorts = int(c.activePorts.Load())
	return
}

// Close releases the io_uring ring and other kernel resources.
func (c *linuxCore) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	// Wait for the reactor to actually return before releasing the ring.
	// cancel() only signals it; uring.Ring.Close unmaps the submission and
	// completion queues, so freeing them while the reactor still holds a
	// pointer into that memory is a use-after-free — it faulted with SIGSEGV in
	// freeRing on every CI run.
	if c.reactorDone != nil {
		<-c.reactorDone
		c.reactorDone = nil
	}
	if c.ring != nil {
		err := c.ring.Close()
		c.ring = nil
		c.rea = nil
		return err
	}
	return nil
}

// iouringListener wraps a TCPListener to use io_uring for accepts.
type iouringListener struct {
	*net.TCPListener
	ring *uring.Ring
	rea  *reactor.Reactor
	ctx  context.Context
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
	resCh := make(chan uring.CQEvent, 1)
	op := uring.Accept(uintptr(fd), 0)
	_, err = l.rea.Queue(op, func(event uring.CQEvent) {
		resCh <- event
	})
	if err != nil {
		return l.TCPListener.Accept()
	}

	var event uring.CQEvent
	select {
	case event = <-resCh:
	case <-l.ctx.Done():
		return nil, l.ctx.Err()
	}

	// Fall back rather than surface the error. http.Server.Serve treats a
	// non-temporary accept error as fatal and stops serving, so returning
	// io_uring's error here means one bad completion takes the listener down
	// for good — which is how a single EINVAL silently ended the management
	// server mid-run. The standard accept path is always available, so an
	// io_uring failure should cost this one connection at most.
	if err := event.Error(); err != nil {
		logger.L.LogWarn("io_uring accept failed, falling back to standard accept",
			"error", err)
		return l.TCPListener.Accept()
	}

	newFd := int(event.Res)

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
		rea:  l.rea,
		fd:   actualFd,
		ctx:  l.ctx,
	}, nil
}

// iouringConn wraps a net.Conn to use io_uring for Read and Write.
type iouringConn struct {
	net.Conn
	ring *uring.Ring
	rea  *reactor.Reactor
	fd   int
	ctx  context.Context
}

func (c *iouringConn) Read(b []byte) (n int, err error) {
	resCh := make(chan uring.CQEvent, 1)
	op := uring.Read(uintptr(c.fd), b, 0)
	_, err = c.rea.Queue(op, func(event uring.CQEvent) {
		resCh <- event
	})
	if err != nil {
		return c.Conn.Read(b)
	}

	var event uring.CQEvent
	select {
	case event = <-resCh:
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}

	if err := event.Error(); err != nil {
		return 0, err
	}
	if event.Res == 0 {
		return 0, io.EOF
	}
	return int(event.Res), nil
}

func (c *iouringConn) Write(b []byte) (n int, err error) {
	resCh := make(chan uring.CQEvent, 1)
	op := uring.Write(uintptr(c.fd), b, 0)
	_, err = c.rea.Queue(op, func(event uring.CQEvent) {
		resCh <- event
	})
	if err != nil {
		return c.Conn.Write(b)
	}

	var event uring.CQEvent
	select {
	case event = <-resCh:
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}

	if err := event.Error(); err != nil {
		return 0, err
	}
	return int(event.Res), nil
}
