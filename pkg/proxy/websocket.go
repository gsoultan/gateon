package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
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
	"github.com/gsoultan/gateon/internal/middleware"
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

// proxyUpgrade hijacks the client connection and tunnels upgraded traffic to the backend.
// It handles the handshake and bidirectional byte streaming. Used when ReverseProxy would
// strip Upgrade headers. Caller must have already selected the target (targetURL).
func (h *ProxyHandler) proxyUpgrade(w http.ResponseWriter, r *http.Request, targetURL *url.URL, state *targetState, start time.Time) {
	logger.L.LogDebug("Hijacking for protocol upgrade",
		"request_id", request.GetID(r),
		"upgrade", r.Header.Get("Upgrade"))

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

	ctx, cancel := context.WithTimeout(r.Context(), upgradeDialTimeout)
	defer cancel()

	var backendConn net.Conn
	var d net.Dialer
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		// err set above
	} else if scheme == "https" {
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

	// 1. PROXY Protocol: If enabled for the target, write the PROXY header before any HTTP data.
	if state.proxyProtocolEnabled {
		// Use r.RemoteAddr which is already resolved to the real client IP by RealIP middleware.
		srcIP, srcPort, srcOK := parseTCPAddr(r.RemoteAddr)
		if conn, ok := r.Context().Value(middleware.ConnContextKey).(net.Conn); ok {
			if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				srcIP, srcPort, srcOK = tcp.IP, uint16(tcp.Port), true
			}
		}
		dstIP, dstPort, dstOK := parseTCPAddrFromNetAddr(backendConn.RemoteAddr())

		if err := writeProxyHeader(backendConn, srcIP, srcPort, srcOK, dstIP, dstPort, dstOK, state.proxyProtocolVersion); err != nil {
			logger.L.LogWarn("Failed to write PROXY header to backend", "error", err, "target", host)
			// Non-fatal, continue with the request
		}
	}

	// Build backend request: preserve Upgrade, Connection, Sec-WebSocket-*; set URL/host
	backendReq := &http.Request{
		Method: r.Method,
		URL: &url.URL{
			Scheme:   scheme,
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

	// X-Forwarded-*: preserve the inbound host, but always normalize the scheme
	// through request.Scheme so an untrusted client cannot spoof X-Forwarded-Proto
	// (consistent with the HTTP proxy path in serve_http.go).
	if backendReq.Header.Get("X-Forwarded-Host") == "" {
		backendReq.Header.Set("X-Forwarded-Host", r.Host)
	}
	backendReq.Header.Set("X-Forwarded-Proto", request.Scheme(r))

	// X-Forwarded-For: append the immediate peer IP to the chain.
	// We use the underlying connection's remote address if available to ensure we
	// append the actual peer, even if RealIP middleware updated r.RemoteAddr.
	peerIP := ""
	if conn, ok := r.Context().Value(middleware.ConnContextKey).(net.Conn); ok {
		if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			peerIP = tcp.IP.String()
		}
	}
	if peerIP == "" {
		peerIP = httputil.StripPort(r.RemoteAddr)
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		var sb strings.Builder
		sb.Grow(len(xff) + len(peerIP) + 2)
		sb.WriteString(xff)
		sb.WriteString(", ")
		sb.WriteString(peerIP)
		backendReq.Header.Set("X-Forwarded-For", sb.String())
	} else {
		backendReq.Header.Set("X-Forwarded-For", peerIP)
	}

	// Force HTTP/1.1 and Upgrade headers for the backend handshake.
	// Many backends (like GitLab) require Connection: upgrade explicitly.
	backendReq.Proto = "HTTP/1.1"
	backendReq.ProtoMajor = 1
	backendReq.ProtoMinor = 1
	backendReq.Header.Set("Connection", "upgrade")

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
		copyWithPooledBuffer(backendConn, clientConn)
		closeWrite(backendConn)
		close(done)
	}()
	copyWithPooledBuffer(clientConn, backendReader)
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
