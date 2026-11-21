// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package drain shuts an http.Server down without dropping a connection it
// has already accepted.
//
// http.Server.Shutdown answers every request a handler has started on, and
// closes every connection that is idle. Between the two is a connection that
// was accepted a moment before the shutdown and whose request had not been
// read yet: net/http reads that request, sees the server is shutting down, and
// closes the connection without a word. The client sees an empty reply. On a
// gateway restarted under traffic that is a handful of failed requests per
// restart, and it is the one failure a socket kept open across the restart
// (ADR 0092) cannot cover, because the old process had already taken the
// connection out of the socket.
//
// Arrivals closes the listener first and lets net/http go on serving until
// every connection accepted before that has had its first request reach the
// handler. Only then does it call Shutdown.
package drain

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// FirstRequestGrace is how long a shutdown waits for a connection that was
// accepted and has not sent a request. A request follows its connection within
// a round trip or a TLS handshake; a connection still silent after this long
// is one a browser opened ahead of need, or a client holding a slot, and is
// closed. net/http's own rule gives it five seconds; every restart with such
// a connection open pays the wait, so this is shorter.
const FirstRequestGrace = time.Second

// pollInterval is how often Shutdown looks for the last arrival to be served.
const pollInterval = time.Millisecond

// arrivalKey is the context key a connection's arrival is stored under.
type arrivalKey struct{}

// arrival is one accepted connection that has not had a request reach the
// handler yet.
type arrival struct {
	conn    net.Conn
	settled atomic.Bool
}

// Arrivals tracks, for one http.Server, the connections that were accepted
// and are still owed their first answer. It is safe for concurrent use.
type Arrivals struct {
	srv *http.Server
	// fresh holds a connection from its accept until its first request
	// reaches the handler or it closes, so it never holds more than the
	// server has open connections, which the listener caps.
	fresh   sync.Map // net.Conn -> *arrival
	pending atomic.Int64
	closing atomic.Bool
	// accepted is closed when the accept loop has returned, after which no
	// connection can be added.
	accepted     chan struct{}
	acceptedOnce sync.Once
}

// Track makes srv count its arrivals. Call it once, after srv's Handler,
// ConnContext and ConnState are set and before it serves.
func Track(srv *http.Server) *Arrivals {
	a := &Arrivals{srv: srv, accepted: make(chan struct{})}
	srv.Handler = a.handler(srv.Handler)
	connContext, connState := srv.ConnContext, srv.ConnState
	srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if connContext != nil {
			ctx = connContext(ctx, c)
		}
		return a.admit(ctx, c)
	}
	srv.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			if v, ok := a.fresh.Load(c); ok {
				if arr, ok := v.(*arrival); ok {
					a.settle(arr)
				}
			}
		}
		if connState != nil {
			connState(c, state)
		}
	}
	return a
}

// admit records c as owed its first answer.
func (a *Arrivals) admit(ctx context.Context, c net.Conn) context.Context {
	arr := &arrival{conn: c}
	a.pending.Add(1)
	a.fresh.Store(c, arr)
	return context.WithValue(ctx, arrivalKey{}, arr)
}

// settle records that arr has been answered, or will never ask.
func (a *Arrivals) settle(arr *arrival) {
	if arr.settled.CompareAndSwap(false, true) {
		a.fresh.Delete(arr.conn)
		a.pending.Add(-1)
	}
}

// handler settles a connection's arrival when its first request gets here.
// net/http decides whether to drop a request before it calls the handler, so
// a request that has reached this point is one it will answer.
func (a *Arrivals) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if arr, ok := r.Context().Value(arrivalKey{}).(*arrival); ok && !arr.settled.Load() {
			a.settle(arr)
		}
		next.ServeHTTP(w, r)
	})
}

// Serve runs serve, which is srv.Serve or srv.ServeTLS on the listener that
// Shutdown will be given. It returns nil when the server stopped because it
// was shut down, and serve's error otherwise.
func (a *Arrivals) Serve(serve func() error) error {
	err := serve()
	a.acceptedOnce.Do(func() { close(a.accepted) })
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	if a.closing.Load() && errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Shutdown stops the server. It closes listener, which is the one Serve is
// accepting on, waits for every connection accepted before that to have its
// first request reach the handler, and then drains the server until ctx
// expires and closes whatever is still open.
//
// The close after a failed drain is what makes ctx a real bound: an event
// stream, a stuck upload or a backend that never answers is cut loose rather
// than holding the process open until it is killed.
//
// A nil listener is for a server whose connections are handed to it by
// something else that stops on its own; its arrivals are waited for the same
// way.
func (a *Arrivals) Shutdown(ctx context.Context, listener io.Closer) error {
	if listener != nil {
		a.closing.Store(true)
		_ = listener.Close()
		// The accept loop may be holding a connection it has taken and not
		// counted yet. Once it has returned there is none.
		select {
		case <-a.accepted:
		case <-ctx.Done():
		}
	}
	a.waitForArrivals(ctx)
	a.closeSilent()
	err := a.srv.Shutdown(ctx)
	if err != nil {
		_ = a.srv.Close()
	}
	return err
}

// closeSilent closes the connections that are still owed a first answer
// because they never asked. net/http would hold the shutdown open five more
// seconds for each before closing it itself.
func (a *Arrivals) closeSilent() {
	a.fresh.Range(func(key, _ any) bool {
		if c, ok := key.(net.Conn); ok {
			_ = c.Close()
		}
		return true
	})
}

// waitForArrivals returns when no connection is owed its first answer, when
// FirstRequestGrace has passed, or when ctx is done.
func (a *Arrivals) waitForArrivals(ctx context.Context) {
	if a.pending.Load() == 0 {
		return
	}
	grace := time.NewTimer(FirstRequestGrace)
	defer grace.Stop()
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for a.pending.Load() != 0 {
		select {
		case <-ctx.Done():
			return
		case <-grace.C:
			return
		case <-tick.C:
		}
	}
}
