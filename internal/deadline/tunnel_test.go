// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package deadline

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// TestAClockReaderEndsOnlyWhenNeitherDirectionMoves: a read that times out
// while the other direction kept the tunnel alive is retried; once nothing
// has moved either way for the idle timeout, the read ends with
// ErrStreamOver.
func TestAClockReaderEndsOnlyWhenNeitherDirectionMoves(t *testing.T) {
	const idle = 200 * time.Millisecond
	clock := NewClock(StreamLimits{Idle: idle})
	quietA, quietB := net.Pipe() // nobody ever writes to quietB's side
	defer quietA.Close()
	defer quietB.Close()
	busyA, busyB := net.Pipe()
	defer busyA.Close()

	// The other direction: a byte every idle/4 for 3 idle timeouts.
	done := make(chan struct{})
	go func() {
		defer close(done)
		w := clock.Writer(busyA)
		tick := time.NewTicker(idle / 4)
		defer tick.Stop()
		for range 12 {
			<-tick.C
			if _, err := w.Write([]byte("x")); err != nil {
				return
			}
		}
	}()
	drained := drain(busyB)
	defer func() { _ = busyB.Close(); <-drained }()

	start := time.Now()
	_, err := clock.Reader(quietA, quietA).Read(make([]byte, 1))
	took := time.Since(start)
	<-done
	if !errors.Is(err, ErrStreamOver) {
		t.Fatalf("read on the quiet side ended with %v, want ErrStreamOver", err)
	}
	if took < 3*idle {
		t.Fatalf("the quiet side ended after %v, while the other side was still moving bytes (until %v)", took, 3*idle)
	}
}

// drain reads c until it is closed; the channel says it has stopped.
func drain(c net.Conn) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()
	return done
}

// TestAClockWithNoBoundsSetsNoDeadline: both bounds disabled is the tunnel
// as it was, ended only by its ends.
func TestAClockWithNoBoundsSetsNoDeadline(t *testing.T) {
	clock := NewClock(StreamLimits{})
	if end, ok := clock.end(); !end.IsZero() || !ok {
		t.Fatalf("end() = %v, %v; want no bound", end, ok)
	}
}

// TestAClockEndsAtItsLifetimeHoweverBusy: the lifetime is measured from the
// start, so activity does not move it. A write in flight when it passes fails
// on its deadline; the next is refused with ErrStreamOver. Either is the end.
func TestAClockEndsAtItsLifetimeHoweverBusy(t *testing.T) {
	const lifetime = 100 * time.Millisecond
	start := time.Now()
	clock := NewClock(StreamLimits{Idle: time.Hour, MaxLifetime: lifetime})
	a, b := net.Pipe()
	defer a.Close()
	drained := drain(b)
	defer func() { _ = b.Close(); <-drained }()
	w := clock.Writer(a)
	for time.Since(start) < 5*time.Second {
		_, err := w.Write([]byte("x"))
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrStreamOver) && !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write: %v", err)
		}
		if took := time.Since(start); took < lifetime*3/4 {
			t.Fatalf("a busy tunnel ended after %v, inside its %v lifetime", took, lifetime)
		}
		return
	}
	t.Fatal("a busy tunnel outlived its 100ms lifetime")
}
