// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/gsoultan/gateon/internal/syncutil"
)

// failOnceListener answers its first Accept with the error the kernel gives a
// process out of file descriptors, and every later one as the listener does.
type failOnceListener struct {
	net.Listener
	failed atomic.Bool
}

func (l *failOnceListener) Accept() (net.Conn, error) {
	if l.failed.CompareAndSwap(false, true) {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	}
	return l.Listener.Accept()
}

// startTCPServerOn is tcpEntrypointFrom with the test's own listener in
// place of the entrypoint's.
func startTCPServerOn(t *testing.T, s *tcpServer, l net.Listener, reg *ShutdownRegistry, wg *syncutil.WaitGroup) {
	t.Helper()
	s.start(l, reg)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), sessionBound)
		defer cancel()
		reg.ShutdownAll(ctx)
		wg.Wait()
	})
}

// TestTheAcceptLoopSurvivesATransientAcceptError: a TCP entrypoint's accept
// loop returned on any error from Accept, and closed the listener on its way
// out. Running out of file descriptors -- which a connection flood on the
// 2-core target reaches at the default ulimit -- made accept(2) fail with
// EMFILE, and from then on the entrypoint accepted nothing, for the life of
// the process, while every other listener in it carried on. net/http's Serve
// backs off and retries on a temporary error; the TCP entrypoint now does the
// same, and only a closed listener ends the loop.
func TestTheAcceptLoopSurvivesATransientAcceptError(t *testing.T) {
	backend, sessions := countingEcho(t)
	ep, deps := tcpEntrypoint(t, "accept-emfile"), mockDepsForInspection(t)
	deps.L4Resolver = routesResolver(t, ep.Id, backend, false)
	wg := &syncutil.WaitGroup{}
	s := newTCPServer(ep, deps, wg)
	l, err := s.listen(ep.Address)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	startTCPServerOn(t, s, &failOnceListener{Listener: l}, deps.ShutdownRegistry, wg)

	// The first Accept fails. If the loop gave up, this connection is accepted
	// by the kernel's backlog and then closed with the listener, and nothing
	// ever echoes.
	_ = echoed(t, dialBounded(t, ep.Address), "after the transient error\n")
	if n := sessions.Load(); n != 1 {
		t.Errorf("the backend was given %d sessions, want 1", n)
	}
}

// TestAPanicServingOneConnectionDoesNotTakeTheEntrypointDown: every connection
// a TCP entrypoint admits is served on a goroutine of its own, and a panic on
// one of them -- in protocol detection, in the PROXY header, in the proxy
// itself -- ended the process, with every other connection on every other
// listener. net/http recovers a handler's panic, logs it and closes that one
// connection; the TCP entrypoint now does the same. The panic is planted in
// the block-list lookup, the first thing asked of every connection, because
// the test can replace that; the recovery is around the whole of handle.
func TestAPanicServingOneConnectionDoesNotTakeTheEntrypointDown(t *testing.T) {
	backend, sessions := countingEcho(t)
	ep, deps := tcpEntrypoint(t, "handler-panic"), mockDepsForInspection(t)
	deps.L4Resolver = routesResolver(t, ep.Id, backend, false)
	wg := &syncutil.WaitGroup{}
	s := newTCPServer(ep, deps, wg)
	var first atomic.Bool
	s.blocked = func(string) bool {
		if first.CompareAndSwap(false, true) {
			panic("planted: the first connection's lookup")
		}
		return false
	}
	l, err := s.listen(ep.Address)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	startTCPServerOn(t, s, l, deps.ShutdownRegistry, wg)

	// The connection whose handler panics is closed, not left open.
	c := dialBounded(t, ep.Address)
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("the connection whose handler panicked was not closed")
	}
	_ = c.Close()

	// And the entrypoint goes on serving.
	next := echoed(t, dialBounded(t, ep.Address), "the next connection\n")
	if n := sessions.Load(); n != 1 {
		t.Errorf("the backend was given %d sessions, want the one connection served after the panic", n)
	}
	_ = next.Close()
	// The slot the panicking connection held is given back, so once its
	// clients are gone the entrypoint shuts down without waiting out a
	// connection nobody is serving.
	ctx, cancel := context.WithTimeout(context.Background(), sessionBound)
	defer cancel()
	deps.ShutdownRegistry.ShutdownAll(ctx)
	if ctx.Err() != nil {
		t.Error("shutdown waited out its deadline: a connection's slot was never released")
	}
}
