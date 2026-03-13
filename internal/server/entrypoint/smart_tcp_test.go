package entrypoint

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
)

func TestPeekedConnReplaysFirst(t *testing.T) {
	// Server reads peeked from conn (consuming it), then wraps conn with peeked.
	// Reads from pc must return peeked first.
	peeked := []byte("GET / HTTP/1.1\r\n")
	srvConn, clientConn := net.Pipe()
	go func() {
		_, _ = clientConn.Write(peeked)
		_ = clientConn.Close()
	}()

	// Consume from srvConn into buf (simulating our peek)
	buf := make([]byte, PeekSize)
	n, _ := io.ReadFull(srvConn, buf)
	gotPeeked := buf[:n]
	if !bytes.Equal(gotPeeked, peeked) {
		t.Fatalf("peek got %q", gotPeeked)
	}

	// Wrap srvConn (now empty) with peeked - replay so HTTP server sees full request
	pc := newPeekedConn(srvConn, peeked)
	all, err := io.ReadAll(pc)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.HasPrefix(all, peeked) {
		t.Errorf("expected prefix %q, got %q", peeked, all)
	}
}

func TestPeekedConnParseHTTP(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
	srvConn, clientConn := net.Pipe()
	go func() {
		_, _ = clientConn.Write([]byte(req))
		_ = clientConn.Close()
	}()

	peeked := make([]byte, PeekSize)
	n, _ := io.ReadFull(srvConn, peeked)
	peeked = peeked[:n]

	if !IsTCPAppHTTP(peeked) {
		t.Fatalf("IsTCPAppHTTP(%q) = false", peeked)
	}

	pc := newPeekedConn(srvConn, peeked)
	r, err := http.ReadRequest(bufio.NewReader(pc))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if r.Method != "GET" || r.URL.Path != "/" {
		t.Errorf("got %s %s", r.Method, r.URL.Path)
	}
}
