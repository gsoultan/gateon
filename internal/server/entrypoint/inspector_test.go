package entrypoint

import "testing"

func TestIsTCPAppHTTP(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"empty", nil, false},
		{"empty slice", []byte{}, false},
		{"HTTP/2 preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), true},
		{"HTTP/2 partial", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n"), false},
		{"GET ", []byte("GET / HTTP/1.1\r\n"), true},
		{"GET short", []byte("GET "), true},
		{"POST ", []byte("POST /api HTTP/1.1\r\n"), true},
		{"HEAD ", []byte("HEAD / HTTP/1.1\r\n"), true},
		{"PUT ", []byte("PUT /x HTTP/1.1\r\n"), true},
		{"DELETE ", []byte("DELETE /x HTTP/1.1\r\n"), true},
		{"OPTIONS ", []byte("OPTIONS * HTTP/1.1\r\n"), true},
		{"PATCH ", []byte("PATCH /x HTTP/1.1\r\n"), true},
		{"GET no space", []byte("GET"), false},
		{"raw bytes", []byte{0x00, 0x01, 0x02, 0x03}, false},
		{"postgres startup", []byte{0x00, 0x00, 0x00, 0x08}, false},
		{"redis", []byte("*1\r\n$4\r\nPING"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTCPAppHTTP(tt.b); got != tt.want {
				t.Errorf("IsTCPAppHTTP(%q) = %v, want %v", tt.b, got, tt.want)
			}
		})
	}
}

func TestIsUDPPacketQUIC(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"short", []byte{0x00, 0x01}, false},
		{"QUIC long header", []byte{0xC0, 0x00, 0x00, 0x00}, true},
		{"QUIC initial", []byte{0xFF, 0x00, 0x00, 0x01}, true},
		{"random udp", []byte{0x00, 0x11, 0x22, 0x33}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUDPPacketQUIC(tt.b); got != tt.want {
				t.Errorf("IsUDPPacketQUIC(...) = %v, want %v", got, tt.want)
			}
		})
	}
}
