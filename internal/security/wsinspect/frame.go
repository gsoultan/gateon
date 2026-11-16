// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package wsinspect

import (
	"encoding/binary"
	"io"
)

// Frame opcodes (RFC 6455 section 5.2).
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

const (
	finBit  = 0x80
	rsvBits = 0x70
	maskBit = 0x80

	// maxControlPayload is the largest control frame the protocol permits.
	maxControlPayload = 125
	// maxHeader is two bytes, an eight-byte length and a four-byte key.
	maxHeader = 14
	// readChunk bounds how far a buffer grows ahead of the bytes that have
	// actually arrived. A frame's declared length is the client's claim; it
	// reserves nothing.
	readChunk = 16 << 10
)

// header is one parsed frame header and its wire bytes.
type header struct {
	wire    [maxHeader]byte
	n       int
	fin     bool
	opcode  byte
	length  uint64
	maskKey [4]byte
}

func (h *header) control() bool { return h.opcode >= opClose }

// readHeader reads one frame header. ok is false when the bytes are not a
// frame a client may send.
func (c *Conn) readHeader(h *header) (ok bool, err error) {
	if _, err = io.ReadFull(c.src, h.wire[:2]); err != nil {
		return false, err
	}
	h.n = 2
	h.fin = h.wire[0]&finBit != 0
	h.opcode = h.wire[0] & 0x0F
	h.length = uint64(h.wire[1] &^ maskBit)

	// A reserved bit means an extension, and none was negotiated. A client
	// frame without a mask is forbidden outright (section 5.1).
	if h.wire[0]&rsvBits != 0 || h.wire[1]&maskBit == 0 {
		return false, nil
	}
	ext := 0
	switch h.length {
	case 126:
		ext = 2
	case 127:
		ext = 8
	}
	if _, err = io.ReadFull(c.src, h.wire[2:2+ext+4]); err != nil {
		return false, err
	}
	switch ext {
	case 2:
		h.length = uint64(binary.BigEndian.Uint16(h.wire[2:4]))
	case 8:
		h.length = binary.BigEndian.Uint64(h.wire[2:10])
		if h.length>>63 != 0 {
			return false, nil
		}
	}
	h.n = 2 + ext + 4
	copy(h.maskKey[:], h.wire[2+ext:h.n])
	return h.valid(c.inMessage || c.passing), nil
}

// valid applies the rules that depend on the opcode and on whether a message
// is already under way.
func (h *header) valid(midMessage bool) bool {
	switch h.opcode {
	case opClose, opPing, opPong:
		return h.fin && h.length <= maxControlPayload
	case opContinuation:
		return midMessage
	case opText, opBinary:
		return !midMessage
	default:
		return false
	}
}

// readFrame reads the next client frame and moves whatever it clears into out.
func (c *Conn) readFrame() error {
	var h header
	ok, err := c.readHeader(&h)
	if err != nil {
		return err
	}
	if !ok {
		return c.refuse(closeProtocolError, ReasonProtocol)
	}
	if h.control() {
		return c.relayControl(&h)
	}
	if c.passing {
		c.relayUnread(&h)
		return nil
	}
	if c.pastLimit(&h) {
		return c.oversize(&h)
	}
	return c.hold(&h)
}

// pastLimit reports whether holding this frame would take the message past
// what one connection may hold.
//
// Two bounds, because a message costs its payload and its framing. The first
// is the one an operator sets. The second stops a client that sends fragments
// of no payload at all for ever: each is six bytes of header that must be kept
// to be forwarded, and the payload bound alone never counts them.
func (c *Conn) pastLimit(h *header) bool {
	limit := uint64(c.opts.MaxMessage)
	if uint64(c.assembled)+h.length > limit {
		return true
	}
	return uint64(len(c.raw))+uint64(h.n)+h.length > limit+limit/4+maxHeader
}

// relayControl forwards a ping, pong or close as it arrived. It may overtake
// the held frames of a message still being assembled, which the protocol
// allows: a control frame may appear between the fragments of a message.
func (c *Conn) relayControl(h *header) error {
	c.out = append(c.out, h.wire[:h.n]...)
	start := len(c.out)
	c.out = append(c.out, make([]byte, h.length)...)
	_, err := io.ReadFull(c.src, c.out[start:])
	return err
}

// relayUnread forwards a frame of a message already past the limit.
func (c *Conn) relayUnread(h *header) {
	c.out = append(c.out, h.wire[:h.n]...)
	c.pass = int64(h.length)
	c.passing = !h.fin
}

// oversize handles the frame that takes a message past MaxMessage.
func (c *Conn) oversize(h *header) error {
	if !c.opts.ForwardOversize {
		return c.refuse(closeMessageTooBig, ReasonOversize)
	}
	if c.opts.OnClose != nil {
		c.opts.OnClose(ReasonOversize)
	}
	// What was held of this message goes first, then the rest unread.
	c.out = append(c.out, c.raw...)
	c.resetMessage()
	c.relayUnread(h)
	return nil
}

// hold reads a data frame's payload into the message being assembled and, on
// its final frame, asks the Inspector.
func (c *Conn) hold(h *header) error {
	if !c.inMessage {
		c.inMessage = true
		c.text = h.opcode == opText
	}
	single := h.fin && len(c.raw) == 0
	c.raw = append(c.raw, h.wire[:h.n]...)
	start := len(c.raw)
	var err error
	if c.raw, err = appendN(c.raw, c.src, int(h.length)); err != nil {
		return err
	}
	payload := c.raw[start:]
	c.assembled += len(payload)

	if single {
		// One frame, the usual case: unmask where it lies, judge it, and
		// put the mask back, so the message is held once.
		mask(payload, h.maskKey)
		verdict := c.judge(payload)
		mask(payload, h.maskKey)
		return c.settle(verdict)
	}
	at := len(c.msg)
	c.msg = append(c.msg, payload...)
	mask(c.msg[at:], h.maskKey)
	if !h.fin {
		return nil
	}
	return c.settle(c.judge(c.msg))
}

func (c *Conn) judge(payload []byte) Verdict {
	if len(payload) == 0 {
		return Allow
	}
	return c.opts.Inspect(payload, c.text)
}

// settle releases a judged message to the backend or closes the connection.
func (c *Conn) settle(v Verdict) error {
	if v != Allow {
		return c.refuse(closePolicyViolation, ReasonRefused)
	}
	if c.outOff == len(c.out) && len(c.out) == 0 {
		c.out, c.raw = c.raw, c.out[:0]
	} else {
		c.out = append(c.out, c.raw...)
	}
	c.resetMessage()
	return nil
}

func (c *Conn) resetMessage() {
	c.inMessage = false
	c.assembled = 0
	c.msg = nil
	if cap(c.raw) > retainCap {
		c.raw = nil
		return
	}
	c.raw = c.raw[:0]
}

// appendN appends exactly n bytes from r to b, growing b only as they arrive.
func appendN(b []byte, r io.Reader, n int) ([]byte, error) {
	for n > 0 {
		step := min(n, readChunk)
		at := len(b)
		b = append(b, make([]byte, step)...)
		if _, err := io.ReadFull(r, b[at:]); err != nil {
			return b, err
		}
		n -= step
	}
	return b, nil
}

// mask applies a frame's masking key in place. Applying it twice restores the
// bytes.
func mask(b []byte, key [4]byte) {
	for i := range b {
		b[i] ^= key[i&3]
	}
}
