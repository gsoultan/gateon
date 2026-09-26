// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"crypto/tls"
	"encoding/binary"
	"strings"
	"testing"
)

// FuzzCalcFingerprints computes JA4 over ClientHelloInfo values built from
// arbitrary bytes -- a superset of what crypto/tls will hand the callback,
// since every field is filled independently. CalcFingerprints runs inside
// GetConfigForClient, and on an HTTP/3 entrypoint crypto/tls runs that
// handshake on a goroutine of its own with no recover: a panic here is a crash
// any client can trigger with one QUIC Initial.
func FuzzCalcFingerprints(f *testing.F) {
	f.Add("example.com", []byte{0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f}, []byte{0x00, 0x00, 0x00, 0x10}, []byte{0x03, 0x04, 0x03, 0x03}, "h2\x00http/1.1")
	f.Add("", []byte{}, []byte{}, []byte{}, "")
	f.Add("10.0.0.1", []byte{0x00}, []byte{0xff}, []byte{0x03}, "\x00\x00x")
	f.Fuzz(func(t *testing.T, sni string, ciphers, exts, versions []byte, alpn string) {
		hello := &tls.ClientHelloInfo{
			ServerName:        sni,
			CipherSuites:      u16s(ciphers),
			Extensions:        u16s(exts),
			SupportedVersions: u16s(versions),
		}
		if alpn != "" {
			hello.SupportedProtos = strings.Split(alpn, "\x00")
		}
		ja4 := CalcFingerprints(hello).JA4

		// ja4_a is 10 characters, then two 12-hex-digit hashes.
		parts := strings.Split(ja4, "_")
		if len(parts) != 3 || len(parts[0]) != 10 || len(parts[1]) != 12 || len(parts[2]) != 12 {
			t.Fatalf("malformed JA4 %q", ja4)
		}
		for _, p := range parts[1:] {
			if strings.Trim(p, "0123456789abcdef") != "" {
				t.Fatalf("JA4 hash part %q is not lower-case hex (full %q)", p, ja4)
			}
		}
	})
}

func u16s(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:]))
	}
	return out
}
