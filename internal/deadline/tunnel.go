// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package deadline

import (
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// ErrStreamOver is what a tunnel's reader or writer returns once the tunnel
// has been idle for its idle timeout, or has reached its maximum lifetime.
var ErrStreamOver = errors.New("stream idle timeout or maximum lifetime reached")

// Clock is the shared timekeeping of one tunnel: a hijacked connection pair
// relaying bytes both ways, as a WebSocket does once its backend has answered
// 101. A byte moved in either direction resets the idle timeout for both, so a
// tunnel where only one side talks -- a server pushing to a silent client --
// stays open; nothing moving in either direction for the idle timeout, or the
// maximum lifetime passing, ends both.
//
// It works through the connections' own deadlines, so it costs no goroutine
// and no timer: each read and write sets the deadline it may run until.
type Clock struct {
	limits StreamLimits
	start  time.Time
	last   atomic.Int64 // when a byte last moved, in unix nanoseconds
}

// NewClock starts a tunnel's clock now.
func NewClock(limits StreamLimits) *Clock {
	now := time.Now()
	c := &Clock{limits: limits, start: now}
	c.last.Store(now.UnixNano())
	return c
}

// end is when the tunnel is over unless a byte moves first, and whether that
// is still ahead. The zero time is no bound.
func (c *Clock) end() (time.Time, bool) {
	end := c.limits.endAt(c.start, time.Unix(0, c.last.Load()))
	return end, end.IsZero() || time.Now().Before(end)
}

func (c *Clock) moved() { c.last.Store(time.Now().UnixNano()) }

// Reader returns r -- which reads from conn, perhaps through a buffer --
// bounded by the clock. A read that times out while the other direction kept
// the tunnel alive is simply retried.
func (c *Clock) Reader(conn net.Conn, r io.Reader) io.Reader {
	return &clockReader{clock: c, conn: conn, r: r}
}

// Writer returns conn as a writer bounded by the clock. A write that cannot
// finish before the tunnel's end -- the peer has stopped reading -- fails.
func (c *Clock) Writer(conn net.Conn) io.Writer {
	return &clockWriter{clock: c, conn: conn}
}

type clockReader struct {
	clock *Clock
	conn  net.Conn
	r     io.Reader
}

func (cr *clockReader) Read(p []byte) (int, error) {
	for {
		end, ok := cr.clock.end()
		if !ok {
			return 0, ErrStreamOver
		}
		_ = cr.conn.SetReadDeadline(end)
		n, err := cr.r.Read(p)
		if n > 0 {
			cr.clock.moved()
		}
		// A timeout with nothing read is only the end if the clock agrees:
		// bytes may have moved the other way meanwhile. A timed-out read
		// leaves a net.Conn, a TLS one included, usable for the next.
		if n == 0 && errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		return n, err
	}
}

type clockWriter struct {
	clock *Clock
	conn  net.Conn
}

func (cw *clockWriter) Write(p []byte) (int, error) {
	end, ok := cw.clock.end()
	if !ok {
		return 0, ErrStreamOver
	}
	_ = cw.conn.SetWriteDeadline(end)
	n, err := cw.conn.Write(p)
	if n > 0 {
		cw.clock.moved()
	}
	return n, err
}
