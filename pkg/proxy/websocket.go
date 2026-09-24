// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/request"
)

const (
	// upgradeDialTimeout is the max time to establish backend connection for WebSocket.
	upgradeDialTimeout = 10 * time.Second
)

// isUpgradeRequest returns true if the request is an HTTP protocol upgrade.
func isUpgradeRequest(r *http.Request) bool {
	return r.Header.Get("Upgrade") != ""
}

// These are what a client is told when the backend leg of an upgrade fails:
// the same three messages as before, naming no address or cause.
var (
	errUpgradeDial  = errors.New("backend unreachable")
	errUpgradeWrite = errors.New("failed to send request to backend")
	errUpgradeRead  = errors.New("failed to read backend response")
)

// proxyUpgrade relays a protocol upgrade to the backend and, only once the
// backend has agreed to switch, hijacks the client connection and tunnels it.
// Caller must have already selected the target (targetURL).
//
// The order is the security property. The Upgrade header is the client's to
// write, and a backend that does not speak the named protocol answers the
// request like any other. That answer is an ordinary response, so it goes back
// through w -- and through every response-phase control the middleware chain
// wrapped around w: the WAF's data-leak inspection, header rewriting, CORS.
// This used to hijack first and write whatever the backend said straight onto
// the socket, past all of them, so adding "Upgrade: x" to any request was
// enough to read a response the WAF would have refused.
func (h *ProxyHandler) proxyUpgrade(w http.ResponseWriter, r *http.Request, targetURL *url.URL, state *targetState, start time.Time) {
	logger.L.LogDebug("Relaying protocol upgrade",
		"request_id", request.GetID(r),
		"upgrade", r.Header.Get("Upgrade"))

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	backendConn, backendBuf, resp, err := h.startUpgrade(r, targetURL, state)
	atomic.AddUint64(&state.requestCount, 1)
	if err != nil {
		atomic.AddUint64(&state.errorCount, 1)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer backendConn.Close()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// Forward non-101 response to client (e.g. 4xx, 5xx from backend),
		// through the chain like any other response.
		atomic.AddUint64(&state.errorCount, 1)
		writeBackendResponse(w, resp)
		return
	}

	// 101 Switching Protocols: record metrics, then tunnel
	atomic.AddUint64(&state.latencySumUs, uint64(time.Since(start).Microseconds()))
	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Forward headers to client, then tunnel
	if err := resp.Write(clientConn); err != nil {
		return
	}
	_ = bufrw.Flush()
	tunnelUpgrade(clientConn, clientReader(clientConn, bufrw.Reader), backendConn, backendBuf)
}

// startUpgrade dials the backend, sends it the upgrade request and reads its
// answer, without touching the client connection. On success the caller owns
// the connection; backendBuf holds any bytes the backend sent past the head.
func (h *ProxyHandler) startUpgrade(r *http.Request, targetURL *url.URL, state *targetState) (net.Conn, *bufio.Reader, *http.Response, error) {
	backendConn, err := h.dialUpgradeBackend(r, targetURL)
	if err != nil {
		return nil, nil, nil, errUpgradeDial
	}

	// 1. PROXY Protocol: If enabled for the target, write the PROXY header before any HTTP data.
	if state.proxyProtocolEnabled {
		writeUpgradeProxyHeader(r, backendConn, state)
	}

	backendReq := newUpgradeRequest(r, targetURL)
	if err := backendReq.Write(backendConn); err != nil {
		_ = backendConn.Close()
		return nil, nil, nil, errUpgradeWrite
	}

	backendBuf := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(backendBuf, backendReq)
	if err != nil {
		_ = backendConn.Close()
		return nil, nil, nil, errUpgradeRead
	}
	return backendConn, backendBuf, resp, nil
}

// upgradeScheme returns the scheme the backend is dialled with, defaulting to
// plain HTTP.
func upgradeScheme(targetURL *url.URL) string {
	if targetURL.Scheme == "" {
		return "http"
	}
	return targetURL.Scheme
}

// dialUpgradeBackend opens the backend connection for an upgrade, over TLS for
// an https target.
func (h *ProxyHandler) dialUpgradeBackend(r *http.Request, targetURL *url.URL) (net.Conn, error) {
	// Ensure HTTP/1.1 for WebSocket (upgrade not supported over HTTP/2)
	scheme := upgradeScheme(targetURL)
	addr := targetURL.Host
	if !strings.Contains(addr, ":") {
		if scheme == "https" {
			addr = net.JoinHostPort(addr, "443")
		} else {
			addr = net.JoinHostPort(addr, "80")
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), upgradeDialTimeout)
	defer cancel()

	var d net.Dialer
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil || scheme != "https" {
		return rawConn, err
	}
	// Reuse the route's backend TLS config (verification ON by default unless
	// the operator set skip_verify); never hardcode InsecureSkipVerify here.
	var tlsCfg *tls.Config
	if h.tlsConfig != nil {
		tlsCfg = h.tlsConfig.Clone()
	} else {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = targetURL.Hostname()
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// writeUpgradeProxyHeader writes the PROXY protocol header for the client
// connection ahead of the upgrade request.
func writeUpgradeProxyHeader(r *http.Request, backendConn net.Conn, state *targetState) {
	// Use r.RemoteAddr which is already resolved to the real client IP by RealIP middleware.
	srcIP, srcPort, srcOK := parseTCPAddr(r.RemoteAddr)
	if conn, ok := r.Context().Value(identity.ConnContextKey).(net.Conn); ok {
		if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			srcIP, srcPort, srcOK = tcp.IP, uint16(tcp.Port), true
		}
	}
	dstIP, dstPort, dstOK := parseTCPAddrFromNetAddr(backendConn.RemoteAddr())

	if err := writeProxyHeader(backendConn, srcIP, srcPort, srcOK, dstIP, dstPort, dstOK, state.proxyProtocolVersion); err != nil {
		logger.L.LogWarn("Failed to write PROXY header to backend", "error", err, "target", backendConn.RemoteAddr().String())
		// Non-fatal, continue with the request
	}
}

// newUpgradeRequest builds the HTTP/1.1 request sent to the backend for an
// upgrade: the client's request with the identity headers normalised.
func newUpgradeRequest(r *http.Request, targetURL *url.URL) *http.Request {
	host := targetURL.Host
	// Build backend request: preserve Upgrade, Connection, Sec-WebSocket-*; set URL/host
	backendReq := &http.Request{
		Method: r.Method,
		URL: &url.URL{
			Scheme:   upgradeScheme(targetURL),
			Host:     host,
			Path:     r.URL.Path,
			RawPath:  r.URL.RawPath,
			RawQuery: r.URL.RawQuery,
		},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header, len(r.Header)),
		Body:       r.Body,
		Host:       host,
		RemoteAddr: r.RemoteAddr,
	}
	backendReq = backendReq.WithContext(r.Context())
	maps.Copy(backendReq.Header, r.Header)

	// Identity headers: the same set rewriteRequest normalises on the HTTP path.
	// maps.Copy above carried every inbound header across, and a backend reads
	// these for who the client is and what name it was reached by, so none of
	// them may reach it as the client wrote them. Forwarded (RFC 7239) is
	// dropped rather than rewritten, which is what the HTTP path does too.
	backendReq.Header.Set("X-Real-IP", request.GetClientIP(r, false))
	backendReq.Header.Set("X-Forwarded-Host", r.Host)
	backendReq.Header.Del("Forwarded")
	backendReq.Header.Set("X-Forwarded-Proto", request.Scheme(r))
	if request.Scheme(r) == "https" {
		backendReq.Header.Set("X-Forwarded-Ssl", "on")
	}
	backendReq.Header.Set("X-Forwarded-For", upgradeForwardedFor(r))

	// Force HTTP/1.1 and Upgrade headers for the backend handshake.
	// Many backends (like GitLab) require Connection: upgrade explicitly.
	backendReq.Header.Set("Connection", "upgrade")
	return backendReq
}

// upgradeForwardedFor appends the immediate peer IP to the X-Forwarded-For chain.
func upgradeForwardedFor(r *http.Request) string {
	// We use the underlying connection's remote address if available to ensure we
	// append the actual peer, even if RealIP middleware updated r.RemoteAddr.
	peerIP := ""
	if conn, ok := r.Context().Value(identity.ConnContextKey).(net.Conn); ok {
		if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			peerIP = tcp.IP.String()
		}
	}
	if peerIP == "" {
		peerIP = httputil.StripPort(r.RemoteAddr)
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peerIP
	}
	var sb strings.Builder
	sb.Grow(len(xff) + len(peerIP) + 2)
	sb.WriteString(xff)
	sb.WriteString(", ")
	sb.WriteString(peerIP)
	return sb.String()
}

// hopByHopHeaders describe one connection, not the message, so a response
// relayed from the backend's connection must not carry them onto the
// client's (RFC 9110 section 7.6.1).
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// writeBackendResponse relays a backend response through w, which is what
// puts it in front of the middleware chain's response-phase controls.
func writeBackendResponse(w http.ResponseWriter, resp *http.Response) {
	for _, field := range resp.Header["Connection"] {
		for _, name := range strings.Split(field, ",") {
			if name = strings.TrimSpace(name); name != "" {
				resp.Header.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		resp.Header.Del(name)
	}
	dst := w.Header()
	for k, vv := range resp.Header {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	copyWithPooledBuffer(w, resp.Body)
}

// clientReader returns the client side of a hijacked connection as a reader
// that starts with whatever net/http had already buffered from it.
//
// The hijack happens only after the backend has answered, and until then the
// server's background read is live on the connection. A byte it took, or
// anything a client sent early, sits in the hijacked bufio.Reader; reading
// the bare connection instead would drop it and corrupt the tunnel's first
// frame.
func clientReader(conn net.Conn, buffered *bufio.Reader) io.Reader {
	n := buffered.Buffered()
	if n == 0 {
		return conn
	}
	head, _ := buffered.Peek(n)
	return io.MultiReader(bytes.NewReader(head), conn)
}

// tunnelUpgrade relays bytes both ways until each side has finished.
func tunnelUpgrade(clientConn net.Conn, fromClient io.Reader, backendConn net.Conn, backendBuf *bufio.Reader) {
	// Bidirectional tunnel: backendBuf has any bytes after response headers,
	// then backendConn streams the rest. Client writes go to backend.
	//
	// Each direction half-closes its destination when its source ends, so the
	// peer sees EOF and can hang up. The client side used to be left open
	// after the backend closed: the client was never told, and this goroutine
	// waited on the client->backend copy for as long as the client cared to
	// keep an apparently live connection -- a goroutine and two sockets per
	// backend-initiated close, held until the client gave up on its own.
	backendReader := io.MultiReader(backendBuf, backendConn)

	done := make(chan struct{})
	go func() {
		copyWithPooledBuffer(backendConn, fromClient)
		closeWrite(backendConn)
		close(done)
	}()
	copyWithPooledBuffer(clientConn, backendReader)
	closeWrite(clientConn)
	<-done
}

// copyWithPooledBuffer streams src→dst reusing a buffer from the shared proxy
// buffer pool, avoiding a fresh 32KB allocation per WebSocket tunnel direction.
func copyWithPooledBuffer(dst io.Writer, src io.Reader) {
	buf := bufferPool.Get()
	defer bufferPool.Put(buf)
	_, _ = io.CopyBuffer(dst, src, buf)
}

// closeWrite half-closes the connection so the peer receives EOF on read.
func closeWrite(c net.Conn) {
	type writeCloser interface {
		CloseWrite() error
	}
	var under = c
	if tc, ok := c.(*tls.Conn); ok {
		under = tc.NetConn()
	}
	if wc, ok := under.(writeCloser); ok {
		_ = wc.CloseWrite()
	}
}
