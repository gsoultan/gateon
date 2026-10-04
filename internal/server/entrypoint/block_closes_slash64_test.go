// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/security/mitigation"
)

// An IPv6 block covers the address's /64 (ADR 0058), so the block event closes
// the open sessions of every address in it -- the host that rotated to
// another address of its /64 included -- but not of an address the allowlist
// names, nor of the neighbouring /64. IPv4 is still closed per address.
func TestABlockClosesTheOpenSessionsOfItsWholeSlashSixtyFour(t *testing.T) {
	const allowlisted = "2001:db8:9:1::aa"
	mitigation.SetAllowlist(mitigation.ParseAllowlist(allowlisted + "/128"))
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })

	o := newOpenConns(16, nil)
	open := func(addr string) net.Conn {
		local, remote := net.Pipe()
		t.Cleanup(func() { _ = local.Close(); _ = remote.Close() })
		o.conns[local] = addr
		return remote
	}
	sameHost := open("2001:db8:9:1::5")
	rotated := open("2001:db8:9:1:ffff::7")
	exempt := open(allowlisted)
	neighbour := open("2001:db8:9:2::5")
	v4 := open("198.51.100.8")

	if n := o.closeByAddr("2001:db8:9:1::5"); n != 2 {
		t.Errorf("closed %d sessions for a block of 2001:db8:9:1::5, want 2 (the address and its /64 sibling)", n)
	}
	for name, c := range map[string]net.Conn{"the blocked address": sameHost, "its /64 sibling": rotated} {
		if !pipeClosed(c) {
			t.Errorf("%s's session was left open", name)
		}
	}
	for name, c := range map[string]net.Conn{"an allowlisted address in the /64": exempt,
		"the neighbouring /64": neighbour, "an IPv4 session": v4} {
		if pipeClosed(c) {
			t.Errorf("%s's session was closed", name)
		}
	}
	if n := o.closeByAddr("198.51.100.9"); n != 0 {
		t.Errorf("a block of 198.51.100.9 closed %d sessions; IPv4 is closed per address", n)
	}
}

// pipeClosed reports whether the other end of a net.Pipe was closed. With the
// write deadline already passed, net.Pipe answers a closed pipe with
// io.ErrClosedPipe and an open one with os.ErrDeadlineExceeded, without
// waiting for either.
func pipeClosed(c net.Conn) bool {
	_ = c.SetWriteDeadline(time.Now())
	_, err := c.Write([]byte{0})
	return errors.Is(err, io.ErrClosedPipe)
}
