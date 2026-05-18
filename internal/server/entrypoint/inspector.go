package entrypoint

import "bytes"

// PeekSize is the number of bytes to read for protocol detection.
// HTTP/2 preface is 24 bytes; HTTP/1.1 methods need at least 4.
const PeekSize = 24

// HTTP/2 connection preface (RFC 7540).
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// HTTP/1.1 method prefixes (must be followed by space).
var http1Methods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
	[]byte("TRACE "),
}

// SSH identification string prefix (RFC 4253).
var sshPreface = []byte("SSH-2.0-")

// RDP TPKT header (0x03 0x00).
var rdpPreface = []byte{0x03, 0x00}

// IsTCPAppHTTP reports whether the first bytes look like HTTP/1.1 or HTTP/2.
// Used for connection-time inspection to route plaintext TCP.
// b should have at least PeekSize bytes when available; fewer bytes are handled.
func IsTCPAppHTTP(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	// HTTP/2 preface (24 bytes)
	if len(b) >= 24 && bytes.Equal(b[:24], http2Preface) {
		return true
	}
	// HTTP/1.1 methods
	for _, m := range http1Methods {
		if len(m) <= len(b) && bytes.Equal(b[:len(m)], m) {
			return true
		}
	}
	return false
}

// IsSSH reports whether the first bytes look like an SSH identification string.
func IsSSH(b []byte) bool {
	return len(b) >= 8 && bytes.Equal(b[:8], sshPreface)
}

// IsRDP reports whether the first bytes look like an RDP TPKT header.
func IsRDP(b []byte) bool {
	return len(b) >= 2 && bytes.Equal(b[:2], rdpPreface)
}

// IsUDPPacketQUIC reports whether the UDP payload looks like a QUIC long-header packet (HTTP/3).
// Used for first-packet inspection. QUIC long header: first byte bits 6-7 = 11 (0xC0).
// Short headers are used after handshake; we rely on connection state for those.
func IsUDPPacketQUIC(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	return b[0]&0xC0 == 0xC0
}
