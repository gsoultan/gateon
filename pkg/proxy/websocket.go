package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// websocketDialTimeout is the max time to establish backend connection for WebSocket.
	websocketDialTimeout = 10 * time.Second
)

// isWebSocketRequest returns true if the request is a WebSocket upgrade.
func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// proxyWebSocket hijacks the client connection and tunnels WebSocket traffic to the backend.
// It handles the handshake and bidirectional byte streaming. Used when ReverseProxy would
// strip Upgrade headers. Caller must have already selected the target (targetURL).
func (h *ProxyHandler) proxyWebSocket(w http.ResponseWriter, r *http.Request, targetURL *url.URL, state *targetState, start time.Time) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Ensure HTTP/1.1 for WebSocket (upgrade not supported over HTTP/2)
	scheme := targetURL.Scheme
	host := targetURL.Host
	if scheme == "" {
		scheme = "http"
	}
	addr := host
	if !strings.Contains(addr, ":") {
		if scheme == "https" {
			addr = net.JoinHostPort(addr, "443")
		} else {
			addr = net.JoinHostPort(addr, "80")
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), websocketDialTimeout)
	defer cancel()

	var backendConn net.Conn
	var d net.Dialer
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		// err set above
	} else if scheme == "https" {
		tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
		} else {
			backendConn = tlsConn
		}
	} else {
		backendConn = rawConn
	}
	if err != nil {
		atomic.AddUint64(&state.requestCount, 1)
		atomic.AddUint64(&state.errorCount, 1)
		writeHijackedError(clientConn, bufrw, http.StatusBadGateway, "backend unreachable")
		return
	}
	defer backendConn.Close()

	// Build backend request: preserve Upgrade, Connection, Sec-WebSocket-*; set URL/host
	backendReq := r.Clone(r.Context())
	backendReq.URL.Scheme = scheme
	backendReq.URL.Host = host
	backendReq.URL.Path = r.URL.Path
	backendReq.URL.RawPath = r.URL.RawPath
	backendReq.URL.RawQuery = r.URL.RawQuery
	backendReq.Host = host
	backendReq.RequestURI = ""

	// Preserve X-Forwarded-* if not set
	if backendReq.Header.Get("X-Forwarded-Host") == "" {
		backendReq.Header.Set("X-Forwarded-Host", r.Host)
	}
	if backendReq.Header.Get("X-Forwarded-Proto") == "" {
		if r.TLS != nil {
			backendReq.Header.Set("X-Forwarded-Proto", "https")
		} else {
			backendReq.Header.Set("X-Forwarded-Proto", "http")
		}
	}

	// Force HTTP/1.1 for upgrade
	backendReq.Proto = "HTTP/1.1"
	backendReq.ProtoMajor = 1
	backendReq.ProtoMinor = 1

	if err := backendReq.Write(backendConn); err != nil {
		atomic.AddUint64(&state.requestCount, 1)
		atomic.AddUint64(&state.errorCount, 1)
		writeHijackedError(clientConn, bufrw, http.StatusBadGateway, "failed to send request to backend")
		return
	}

	backendBuf := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(backendBuf, backendReq)
	if err != nil {
		atomic.AddUint64(&state.requestCount, 1)
		atomic.AddUint64(&state.errorCount, 1)
		writeHijackedError(clientConn, bufrw, http.StatusBadGateway, "failed to read backend response")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// Forward non-101 response to client (e.g. 4xx, 5xx from backend)
		atomic.AddUint64(&state.requestCount, 1)
		atomic.AddUint64(&state.errorCount, 1)
		_ = resp.Write(clientConn)
		_ = bufrw.Flush()
		return
	}

	// 101 Switching Protocols: record metrics, then tunnel
	atomic.AddUint64(&state.requestCount, 1)
	atomic.AddUint64(&state.latencySumMs, uint64(time.Since(start).Milliseconds()))

	// Forward headers to client, then tunnel
	if err := resp.Write(clientConn); err != nil {
		return
	}
	_ = bufrw.Flush()

	// Bidirectional tunnel: backendBuf has any bytes after response headers,
	// then backendConn streams the rest. Client writes go to backend.
	backendReader := io.MultiReader(backendBuf, backendConn)

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(backendConn, clientConn)
		closeWrite(backendConn)
		close(done)
	}()
	_, _ = io.Copy(clientConn, backendReader)
	<-done
}

// closeWrite half-closes the connection so the peer receives EOF on read.
func closeWrite(c net.Conn) {
	type writeCloser interface {
		CloseWrite() error
	}
	var under net.Conn = c
	if tc, ok := c.(*tls.Conn); ok {
		under = tc.NetConn()
	}
	if wc, ok := under.(writeCloser); ok {
		_ = wc.CloseWrite()
	}
}

func writeHijackedError(conn net.Conn, bufrw *bufio.ReadWriter, code int, msg string) {
	resp := &http.Response{
		StatusCode: code,
		Status:     http.StatusText(code),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(msg)),
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.ContentLength = int64(len(msg))
	_ = resp.Write(conn)
	_ = bufrw.Flush()
}
