// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package wsinspect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

var testKey = [4]byte{0x11, 0x22, 0x33, 0x44}

// clientFrame builds one masked client frame.
func clientFrame(fin bool, opcode byte, payload string) []byte {
	b0 := opcode
	if fin {
		b0 |= finBit
	}
	out := []byte{b0}
	switch n := len(payload); {
	case n <= 125:
		out = append(out, maskBit|byte(n))
	case n <= 0xFFFF:
		out = append(out, maskBit|126)
		out = binary.BigEndian.AppendUint16(out, uint16(n))
	default:
		out = append(out, maskBit|127)
		out = binary.BigEndian.AppendUint64(out, uint64(n))
	}
	out = append(out, testKey[:]...)
	body := []byte(payload)
	mask(body, testKey)
	return append(out, body...)
}

// refuseContaining refuses any message holding needle, and records what it saw.
func refuseContaining(needle string, seen *[]string) Inspector {
	return func(p []byte, _ bool) Verdict {
		*seen = append(*seen, string(p))
		if strings.Contains(string(p), needle) {
			return Refuse
		}
		return Allow
	}
}

// run feeds wire to an inspected connection and returns what reached the
// backend, what the client was sent, and the reasons reported.
func run(t *testing.T, wire []byte, opts Options) (toBackend, toClient []byte, reasons []Reason) {
	t.Helper()
	client, gateway := net.Pipe()
	opts.OnClose = func(r Reason) { reasons = append(reasons, r) }
	conn := NewConn(gateway, nil, opts)

	clientGot := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(client)
		clientGot <- b
	}()
	go func() {
		_, _ = client.Write(wire)
		// The client stops sending; a real one would wait for the reply.
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	}()

	toBackend = readUntilDone(conn, len(wire))
	_ = conn.Close()
	return toBackend, <-clientGot, reasons
}

// readUntilDone reads until the connection ends or everything sent has been
// relayed.
func readUntilDone(conn *Conn, want int) []byte {
	var got []byte
	buf := make([]byte, 512)
	for len(got) < want {
		n, err := conn.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}
	return got
}

func TestAllowedMessagesReachTheBackendByteForByte(t *testing.T) {
	var seen []string
	wire := append(clientFrame(true, opText, `{"q":"hello"}`), clientFrame(true, opBinary, "second")...)

	toBackend, toClient, reasons := run(t, wire, Options{Inspect: refuseContaining("attack", &seen)})

	if !bytes.Equal(toBackend, wire) {
		t.Errorf("the backend did not get the client's bytes unchanged:\n got %x\nwant %x", toBackend, wire)
	}
	if len(seen) != 2 || seen[0] != `{"q":"hello"}` || seen[1] != "second" {
		t.Errorf("the inspector saw %q, want both payloads unmasked", seen)
	}
	if len(toClient) != 0 || len(reasons) != 0 {
		t.Errorf("a clean connection was closed: client got %x, reasons %v", toClient, reasons)
	}
}

func TestRefusedMessageNeverReachesTheBackend(t *testing.T) {
	var seen []string
	clean := clientFrame(true, opText, "first")
	wire := append(bytes.Clone(clean), clientFrame(true, opText, "an attack here")...)
	wire = append(wire, clientFrame(true, opText, "after")...)

	toBackend, toClient, reasons := run(t, wire, Options{Inspect: refuseContaining("attack", &seen)})

	if !bytes.Equal(toBackend, clean) {
		t.Errorf("the backend got %x, want only the first message %x", toBackend, clean)
	}
	if want := []byte{0x88, 2, 0x03, 0xF0}; !bytes.Equal(toClient, want) {
		t.Errorf("the client got %x, want a close frame with code 1008 (%x)", toClient, want)
	}
	if len(reasons) != 1 || reasons[0] != ReasonRefused {
		t.Errorf("reasons = %v, want one %q", reasons, ReasonRefused)
	}
}

// A payload split across frames is one message to the backend, so it is one
// message to the inspector. Judging frames one at a time would let "att" and
// "ack" through separately.
func TestFragmentedMessageIsJudgedWhole(t *testing.T) {
	var seen []string
	wire := append(clientFrame(false, opText, "an att"), clientFrame(false, opContinuation, "")...)
	wire = append(wire, clientFrame(true, opContinuation, "ack here")...)

	toBackend, _, reasons := run(t, wire, Options{Inspect: refuseContaining("attack", &seen)})

	if len(toBackend) != 0 {
		t.Errorf("fragments of a refused message reached the backend: %x", toBackend)
	}
	if len(seen) != 1 || seen[0] != "an attack here" {
		t.Errorf("the inspector saw %q, want the reassembled message once", seen)
	}
	if len(reasons) != 1 || reasons[0] != ReasonRefused {
		t.Errorf("reasons = %v, want one %q", reasons, ReasonRefused)
	}
}

func TestFragmentsAndInterleavedPingAreRelayed(t *testing.T) {
	var seen []string
	first := clientFrame(false, opText, "hel")
	ping := clientFrame(true, opPing, "p")
	last := clientFrame(true, opContinuation, "lo")
	wire := append(append(bytes.Clone(first), ping...), last...)

	toBackend, _, reasons := run(t, wire, Options{Inspect: refuseContaining("attack", &seen)})

	// The ping overtakes the held fragment, which the protocol allows.
	want := append(append(bytes.Clone(ping), first...), last...)
	if !bytes.Equal(toBackend, want) {
		t.Errorf("got %x\nwant %x", toBackend, want)
	}
	if len(seen) != 1 || seen[0] != "hello" || len(reasons) != 0 {
		t.Errorf("seen %q reasons %v, want the whole message and no close", seen, reasons)
	}
}

func TestOversizeMessage(t *testing.T) {
	big := strings.Repeat("a", 200) + "attack"
	wire := clientFrame(true, opText, big)

	t.Run("is refused, so padding buys nothing", func(t *testing.T) {
		var seen []string
		toBackend, toClient, reasons := run(t, wire, Options{MaxMessage: 100, Inspect: refuseContaining("attack", &seen)})
		if len(toBackend) != 0 {
			t.Errorf("%d bytes of an oversize message reached the backend", len(toBackend))
		}
		if want := []byte{0x88, 2, 0x03, 0xF1}; !bytes.Equal(toClient, want) {
			t.Errorf("the client got %x, want close 1009 (%x)", toClient, want)
		}
		if len(reasons) != 1 || reasons[0] != ReasonOversize {
			t.Errorf("reasons = %v", reasons)
		}
	})

	t.Run("is forwarded unread where the route only records", func(t *testing.T) {
		var seen []string
		after := clientFrame(true, opText, "next")
		both := append(bytes.Clone(wire), after...)
		toBackend, toClient, reasons := run(t, both, Options{MaxMessage: 100, ForwardOversize: true, Inspect: refuseContaining("attack", &seen)})
		if !bytes.Equal(toBackend, both) {
			t.Errorf("the backend got %d bytes, want all %d unchanged", len(toBackend), len(both))
		}
		if len(toClient) != 0 || len(reasons) != 1 || reasons[0] != ReasonOversize {
			t.Errorf("client got %x, reasons %v; want no close and one oversize", toClient, reasons)
		}
		if len(seen) != 1 || seen[0] != "next" {
			t.Errorf("the inspector saw %q, want only the message after the oversize one", seen)
		}
	})
}

func TestFramesAClientMayNotSendCloseTheConnection(t *testing.T) {
	unmasked := []byte{finBit | opText, 3, 'a', 'b', 'c'}
	compressed := clientFrame(true, opText, "abc")
	compressed[0] |= 0x40
	for name, wire := range map[string][]byte{
		"unmasked":                       unmasked,
		"an extension bit":               compressed,
		"a continuation of nothing":      clientFrame(true, opContinuation, "abc"),
		"a new message inside a message": append(clientFrame(false, opText, "a"), clientFrame(true, opText, "b")...),
		"a fragmented ping":              clientFrame(false, opPing, "p"),
		"an unknown opcode":              clientFrame(true, 0x3, "abc"),
	} {
		t.Run(name, func(t *testing.T) {
			var seen []string
			toBackend, toClient, reasons := run(t, wire, Options{Inspect: refuseContaining("attack", &seen)})
			if len(toBackend) != 0 {
				t.Errorf("%x reached the backend", toBackend)
			}
			if want := []byte{0x88, 2, 0x03, 0xEA}; !bytes.Equal(toClient, want) {
				t.Errorf("the client got %x, want close 1002 (%x)", toClient, want)
			}
			if len(reasons) != 1 || reasons[0] != ReasonProtocol {
				t.Errorf("reasons = %v", reasons)
			}
		})
	}
}

// Fragments with no payload cost six bytes each to hold and nothing against
// the payload limit, so the limit on what is held has to count them.
func TestEmptyFragmentsCannotGrowWithoutBound(t *testing.T) {
	wire := clientFrame(false, opText, "a")
	for range 1000 {
		wire = append(wire, clientFrame(false, opContinuation, "")...)
	}
	var seen []string
	toBackend, _, reasons := run(t, wire, Options{MaxMessage: 64, Inspect: refuseContaining("attack", &seen)})
	if len(toBackend) != 0 {
		t.Errorf("%d bytes reached the backend", len(toBackend))
	}
	if len(reasons) != 1 || reasons[0] != ReasonOversize {
		t.Errorf("reasons = %v, want the connection closed as oversize", reasons)
	}
}

// Bytes net/http read before the handler took the connection are the start of
// the first frame; they are inspected like the rest.
func TestEarlyBytesAreInspected(t *testing.T) {
	wire := clientFrame(true, opText, "an attack here")
	client, gateway := net.Pipe()
	defer client.Close()
	var seen []string
	conn := NewConn(gateway, wire[:5], Options{Inspect: refuseContaining("attack", &seen)})
	go func() {
		_, _ = client.Write(wire[5:])
		_, _ = io.Copy(io.Discard, client)
	}()
	n, err := conn.Read(make([]byte, 64))
	if n != 0 || !errors.Is(err, ErrClosed) {
		t.Errorf("Read = %d, %v; want the message refused", n, err)
	}
}

// FuzzClientBytes holds the parser to what it promises for any bytes a client
// sends: it does not panic, it never hands the inspector more than the limit,
// and it never gives the backend more than the client sent.
func FuzzClientBytes(f *testing.F) {
	f.Add(clientFrame(true, opText, "hello"), 64)
	f.Add(append(clientFrame(false, opText, "he"), clientFrame(true, opContinuation, "llo")...), 3)
	f.Add([]byte{0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 16)
	f.Fuzz(func(t *testing.T, wire []byte, limit int) {
		if limit <= 0 || limit > 1<<12 {
			limit = 64
		}
		conn := NewConn(nopConn{}, wire, Options{MaxMessage: limit, Inspect: func(p []byte, _ bool) Verdict {
			if len(p) > limit {
				t.Fatalf("the inspector was handed %d bytes past a limit of %d", len(p), limit)
			}
			return Allow
		}})
		out, _ := io.ReadAll(conn)
		if len(out) > len(wire) {
			t.Fatalf("%d bytes out of %d in", len(out), len(wire))
		}
	})
}

// nopConn is a connection with nothing on it; the fuzz target supplies the
// client's bytes as early bytes.
type nopConn struct{ net.Conn }

func (nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }
