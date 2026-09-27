// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package phantom is the seam between the gateway's listeners and its data
// path: what OptimizeListener puts in front of net/http, what ProxyL4 does with
// an L4 session, and what the Diagnostics page is told about both.
//
// It used to offer two accelerations and neither survived measurement.
// GATEON_PHANTOM=1 wrapped every listener in an io_uring reactor; on two CPUs it
// was 6.7x slower per HTTP round trip, 31x slower per L4 echo, a tenth of the
// standard path's L4 throughput, and it kept 8% of a core busy while idle --
// besides ignoring deadlines and never unblocking Accept on Close, which hung
// Connection: close responses and graceful shutdown. The AF_XDP path created a
// socket and then returned an error on every call. Both are gone; the numbers
// are in the commit that removed them, and datapath_bench_test.go reproduces
// them for any engine proposed in their place.
package phantom

import (
	"context"
	"io"
	"net"
	"os"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/pkg/l4"
)

// PhantomCore is the data-path engine behind the gateway's listeners.
type PhantomCore interface {
	// ProxyL4 dials targetAddr and copies bytes between it and client in both
	// directions until either side is done, then closes both. When the dial
	// fails it returns the error and leaves client open for the caller.
	ProxyL4(ctx context.Context, client net.Conn, targetAddr string) error

	// OptimizeListener returns l unchanged. Go's netpoller is the fastest
	// listener measured here; see datapath_bench_test.go.
	OptimizeListener(l net.Listener) net.Listener

	// GetStatus reports the engine actually in use.
	GetStatus() (enabled bool, engine string, activePorts int)

	// Close releases the core. It holds nothing, so it never fails.
	Close() error
}

// NewPhantomCore returns the gateway's data-path engine.
func NewPhantomCore() PhantomCore {
	noteRetiredSwitches()
	return core{}
}

// retiredSwitches are environment variables that used to select an engine
// this package no longer has.
var retiredSwitches = []string{"GATEON_PHANTOM", "GATEON_XDP_IFACE"}

// retiredNotice makes the notice below once per process, however many cores
// are built.
var retiredNotice sync.Once

// noteRetiredSwitches says, once, that a retired switch is set and does
// nothing. An operator who set GATEON_PHANTOM=1 turned something on; silently
// ignoring it would leave them believing it is still on.
func noteRetiredSwitches() {
	for _, name := range retiredSwitches {
		if v := os.Getenv(name); v != "" {
			retiredNotice.Do(func() {
				logger.L.LogWarn("GATEON_PHANTOM and GATEON_XDP_IFACE no longer change anything: "+
					"the io_uring listener measured slower than the standard path and was removed, "+
					"and the AF_XDP path never moved a byte",
					"variable", name, "value", v)
			})
			return
		}
	}
}

type core struct{}

func (core) ProxyL4(ctx context.Context, client net.Conn, targetAddr string) error {
	dialer := net.Dialer{}
	backend, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		// Not closed here. The caller checks this error and falls through to
		// its own handling -- protocol inspection, then a resolved proxy -- so
		// closing the client would leave that fall-through working on a dead
		// socket. The entrypoint reaches this with an empty target, which never
		// dials, so every connection on that path was reset before the
		// inspector saw it. Report the refusal; leave the connection alone.
		return err
	}
	pipe(client, backend)
	return nil
}

// pipe copies a and b into each other until either direction ends, then
// closes both.
//
// Whichever direction finishes first closes both sides. Without that the two
// copies were waited on together while neither could end the other: a client
// that disconnects while the backend holds its side open -- any protocol
// where the server speaks only when spoken to -- left the second copy blocked
// forever, with the Close calls deferred behind the wait for it. One goroutine
// and two sockets per disconnected client, held for the life of the process.
func pipe(a, b net.Conn) {
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer shutdown()
		copyConn(a, b)
	}()
	copyConn(b, a)
	shutdown()
	<-done
}

// copyConn copies src to dst with splice(2) where the kernel can, and through
// a user-space buffer where it cannot.
func copyConn(dst, src net.Conn) {
	if _, err := l4.SpliceCopy(dst, src); err != nil {
		_, _ = io.Copy(dst, src)
	}
}

func (core) OptimizeListener(l net.Listener) net.Listener { return l }

func (core) GetStatus() (enabled bool, engine string, activePorts int) {
	return false, "standard", 0
}

func (core) Close() error { return nil }
