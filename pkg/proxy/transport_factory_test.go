// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestBackendTransportFactory_TransportKinds(t *testing.T) {
	f := newBackendTransportFactory(&tls.Config{InsecureSkipVerify: true}, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)

	// h2 and h2c are net/http transports speaking only HTTP/2; plain http
	// keeps HTTP/1 and negotiates h2 opportunistically.
	tests := []struct {
		name              string
		url               string
		http3             bool
		http1, h2, h2c    bool
		checkProtocolsSet bool
	}{
		{name: "http", url: "http://backend:8080"},
		{name: "h2", url: "h2://backend:443", h2: true, checkProtocolsSet: true},
		{name: "h2c", url: "h2c://backend:50051", h2c: true, checkProtocolsSet: true},
		{name: "h3", url: "h3://backend:443", http3: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := f.TransportFor(newTargetState(tt.url, 1), req)
			if tt.http3 {
				if _, ok := rt.(*http3.Transport); !ok {
					t.Fatalf("expected *http3.Transport, got %T", rt)
				}
				return
			}
			tpt, ok := rt.(*http.Transport)
			if !ok {
				t.Fatalf("expected *http.Transport, got %T", rt)
			}
			if !tt.checkProtocolsSet {
				return
			}
			p := tpt.Protocols
			if p == nil || p.HTTP1() != tt.http1 || p.HTTP2() != tt.h2 || p.UnencryptedHTTP2() != tt.h2c {
				t.Fatalf("protocols = %v, want http1=%t h2=%t h2c=%t", p, tt.http1, tt.h2, tt.h2c)
			}
			if tpt.HTTP2 == nil || tpt.HTTP2.SendPingTimeout != h2SendPingTimeout || tpt.HTTP2.PingTimeout != h2PingTimeout {
				t.Fatalf("HTTP/2 ping settings = %+v, want %v/%v", tpt.HTTP2, h2SendPingTimeout, h2PingTimeout)
			}
		})
	}
}

// The h2 and h2c transports moved from x/net's http2.Transport to net/http's
// own HTTP/2 client when x/net deprecated the former. A type check cannot say
// they still speak HTTP/2 to a backend, so each makes a real request.
func TestBackendTransportFactory_HTTP2TransportsSpeakHTTP2(t *testing.T) {
	proto := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	})

	tlsBackend := httptest.NewUnstartedServer(proto)
	tlsBackend.EnableHTTP2 = true
	tlsBackend.StartTLS()
	t.Cleanup(tlsBackend.Close)

	h2cProtocols := new(http.Protocols)
	h2cProtocols.SetUnencryptedHTTP2(true)
	h2cBackend := httptest.NewUnstartedServer(proto)
	h2cBackend.Config.Protocols = h2cProtocols
	h2cBackend.Start()
	t.Cleanup(h2cBackend.Close)

	f := newBackendTransportFactory(&tls.Config{InsecureSkipVerify: true}, nil, nil)
	for _, tc := range []struct{ name, target string }{
		{"h2", "h2://" + tlsBackend.Listener.Addr().String()},
		{"h2c", "h2c://" + h2cBackend.Listener.Addr().String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := roundTripBody(t, f, tc.target); got != "HTTP/2.0" {
				t.Fatalf("the backend was reached over %q, want HTTP/2.0", got)
			}
		})
	}
}

// A backend configured as h2 that will not negotiate HTTP/2 is refused, not
// silently spoken to in HTTP/1.
func TestBackendTransportFactory_H2RefusesABackendThatWillNotNegotiateIt(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(backend.Close)

	f := newBackendTransportFactory(&tls.Config{InsecureSkipVerify: true}, nil, nil)
	target := "h2://" + backend.Listener.Addr().String()
	rt := &targetBoundRoundTripper{state: newTargetState(target, 1), factory: f}
	req := httptest.NewRequest(http.MethodGet, target+"/", nil)
	req.RequestURI = ""
	resp, err := rt.RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("an h2 backend speaking only HTTP/1 was accepted")
	}
}

// roundTripBody sends a GET to target through the factory's transport for it
// and returns the response body.
func roundTripBody(t *testing.T, f *backendTransportFactory, target string) string {
	t.Helper()
	rt := &targetBoundRoundTripper{state: newTargetState(target, 1), factory: f}
	req := httptest.NewRequest(http.MethodGet, target+"/", nil)
	req.RequestURI = ""
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip to %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the response from %s: %v", target, err)
	}
	return string(body)
}

func TestBackendTransportFactory_ProxyProtocolDisablesHTTP2(t *testing.T) {
	f := newBackendTransportFactory(&tls.Config{InsecureSkipVerify: true}, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "https://localhost", nil)
	s := newTargetStateWithProxy("https://backend:443", 1, true, gateonv1.ProxyProtocolVersion_PROXY_PROTOCOL_VERSION_V1)

	rt := f.TransportFor(s, req)
	tpt, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", rt)
	}
	if tpt.ForceAttemptHTTP2 {
		t.Fatal("expected ForceAttemptHTTP2=false when PROXY protocol is enabled")
	}
	if !tpt.DisableKeepAlives {
		t.Fatal("expected DisableKeepAlives=true when PROXY protocol is enabled")
	}
}

func TestBackendTransportFactory_DynamicIdentityChangesTransportCacheKey(t *testing.T) {
	selector := &tlsClientIdentitySelector{
		strategy: gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER,
		identities: []tlsClientIdentity{
			{id: "tenant-a", cacheKey: "|cert:0", matchHeader: "X-Tenant", matchHeaderValue: "a"},
			{id: "tenant-b", cacheKey: "|cert:1", matchHeader: "X-Tenant", matchHeaderValue: "b"},
		},
	}
	f := newBackendTransportFactory(&tls.Config{InsecureSkipVerify: true}, nil, selector)
	s := newTargetState("https://backend:443", 1)

	reqA := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	reqA.Header.Set("X-Tenant", "a")
	reqB := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	reqB.Header.Set("X-Tenant", "b")

	rtA := f.TransportFor(s, reqA)
	rtB := f.TransportFor(s, reqB)

	if rtA == rtB {
		t.Fatal("expected different transports for different dynamic mTLS identities")
	}
}

func TestWriteProxyHeader(t *testing.T) {
	backendAddr := &net.TCPAddr{IP: net.ParseIP("10.10.10.10"), Port: 8080}

	t.Run("v1", func(t *testing.T) {
		conn := &recordingConn{}
		err := writeProxyHeaderByAddr(conn, "192.168.1.10:50000", backendAddr, gateonv1.ProxyProtocolVersion_PROXY_PROTOCOL_VERSION_V1)
		if err != nil {
			t.Fatalf("writeProxyHeaderByAddr(v1) returned error: %v", err)
		}

		wantPrefix := "PROXY TCP4 192.168.1.10 10.10.10.10 50000 8080\r\n"
		if got := conn.String(); got != wantPrefix {
			t.Fatalf("unexpected PROXY v1 header\nwant: %q\n got: %q", wantPrefix, got)
		}
	})

	t.Run("v2", func(t *testing.T) {
		conn := &recordingConn{}
		err := writeProxyHeaderByAddr(conn, "192.168.1.10:50000", backendAddr, gateonv1.ProxyProtocolVersion_PROXY_PROTOCOL_VERSION_V2)
		if err != nil {
			t.Fatalf("writeProxyHeaderByAddr(v2) returned error: %v", err)
		}

		b := conn.Bytes()
		if len(b) < 16 {
			t.Fatalf("proxy v2 header too short: %d", len(b))
		}
		sig := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
		if !bytes.Equal(b[:12], sig) {
			t.Fatalf("invalid proxy v2 signature: %x", b[:12])
		}
		if b[12] != 0x21 {
			t.Fatalf("unexpected v2 version/command byte: %x", b[12])
		}
	})
}

type recordingConn struct {
	bytes.Buffer
}

func (*recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*recordingConn) Close() error                     { return nil }
func (*recordingConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*recordingConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*recordingConn) SetDeadline(time.Time) error      { return nil }
func (*recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingConn) SetWriteDeadline(time.Time) error { return nil }
