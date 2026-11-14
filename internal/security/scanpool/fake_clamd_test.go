// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package scanpool

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeClamd is a scanner on a loopback listener whose behaviour a test sets
// and may change while it runs.
type fakeClamd struct {
	addr     string
	accepted atomic.Int64
	// sawConn receives once per accepted connection, for a test that must
	// wait for a scan to be under way.
	sawConn chan struct{}
	// done is closed when the test ends, to release a behaviour that waits.
	done chan struct{}

	mu       sync.Mutex
	behave   func(net.Conn)
	received [][]byte
}

func newFakeClamd(t *testing.T, behave func(*fakeClamd, net.Conn)) *fakeClamd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeClamd{addr: "tcp://" + ln.Addr().String(), done: make(chan struct{}), sawConn: make(chan struct{}, 64)}
	f.become(behave)
	var conns sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		close(f.done)
		conns.Wait()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.accepted.Add(1)
			select {
			case f.sawConn <- struct{}{}:
			default:
			}
			f.mu.Lock()
			behave := f.behave
			f.mu.Unlock()
			conns.Go(func() { behave(c) })
		}
	}()
	return f
}

func (f *fakeClamd) become(behave func(*fakeClamd, net.Conn)) {
	f.mu.Lock()
	f.behave = func(c net.Conn) { behave(f, c) }
	f.mu.Unlock()
}

func (f *fakeClamd) files() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.received...)
}

// readInstream reads the command and every chunk, and reports the file.
func readInstream(c net.Conn) ([]byte, bool) {
	r := bufio.NewReader(c)
	if line, err := r.ReadString('\n'); err != nil || line != instreamCommand {
		return nil, false
	}
	var file bytes.Buffer
	for {
		var size [4]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return nil, false
		}
		n := binary.BigEndian.Uint32(size[:])
		if n == 0 {
			return file.Bytes(), true
		}
		if _, err := io.CopyN(&file, r, int64(n)); err != nil {
			return nil, false
		}
	}
}

// answers reads a whole upload and replies with reply.
func answers(reply string) func(*fakeClamd, net.Conn) {
	return func(f *fakeClamd, c net.Conn) {
		defer func() { _ = c.Close() }()
		file, ok := readInstream(c)
		if !ok {
			return
		}
		f.mu.Lock()
		f.received = append(f.received, file)
		f.mu.Unlock()
		_, _ = io.WriteString(c, reply)
	}
}

// hangsUp closes every connection as soon as it is made.
func hangsUp(_ *fakeClamd, c net.Conn) { _ = c.Close() }

// readsAndNeverAnswers takes the whole upload and then says nothing.
func readsAndNeverAnswers(_ *fakeClamd, c net.Conn) {
	_, _ = io.Copy(io.Discard, c)
}

// neverReads accepts the connection and does not read from it, so a sender
// fills the socket buffers and blocks.
func neverReads(f *fakeClamd, c net.Conn) {
	<-f.done
	_ = c.Close()
}

// pongs answers a PING.
func pongs(_ *fakeClamd, c net.Conn) {
	defer func() { _ = c.Close() }()
	if line, err := bufio.NewReader(c).ReadString('\n'); err == nil && line == pingCommand {
		_, _ = io.WriteString(c, pongReply+"\n")
	}
}

const (
	clean = "stream: OK\n"
	eicar = "stream: Win.Test.EICAR_HDB-1 FOUND\n"
)
