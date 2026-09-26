// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bytes"
	"testing"
)

// FuzzProtocolDetection runs the first-bytes classifiers over arbitrary input.
// They run on the per-connection goroutine of a plaintext TCP entrypoint and
// the UDP accept loop, neither of which has a recover, so a bounds error here
// would be a process crash triggered by the first packet of a connection.
func FuzzProtocolDetection(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		[]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
		[]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
		[]byte("PRI * HTTP/2.0\r\n"),
		[]byte("SSH-2.0-OpenSSH_9.6\r\n"),
		{0x03, 0x00, 0x00, 0x13},
		{0xc0, 0x00, 0x00, 0x01, 0x08},
		[]byte("G"),
		[]byte("CONNECT "),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		isHTTP := IsTCPAppHTTP(b)
		isSSH := IsSSH(b)
		isRDP := IsRDP(b)
		_ = IsUDPPacketQUIC(b)

		if isHTTP {
			known := len(b) >= len(http2Preface) && bytes.Equal(b[:len(http2Preface)], http2Preface)
			for _, m := range http1Methods {
				known = known || bytes.HasPrefix(b, m)
			}
			if !known {
				t.Fatalf("IsTCPAppHTTP(%q) = true without a method or the h2 preface", b)
			}
		}
		if isSSH && !bytes.HasPrefix(b, sshPreface) {
			t.Fatalf("IsSSH(%q) = true without the SSH identification prefix", b)
		}
		if isRDP && !bytes.HasPrefix(b, rdpPreface) {
			t.Fatalf("IsRDP(%q) = true without the TPKT header", b)
		}
	})
}
