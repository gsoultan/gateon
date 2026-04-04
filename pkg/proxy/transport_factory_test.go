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
	"golang.org/x/net/http2"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestBackendTransportFactory_TransportKinds(t *testing.T) {
	f := newBackendTransportFactory(&tls.Config{InsecureSkipVerify: true}, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)

	tests := []struct {
		name string
		url  string
		want any
	}{
		{name: "http", url: "http://backend:8080", want: &http.Transport{}},
		{name: "h2", url: "h2://backend:443", want: &http2.Transport{}},
		{name: "h2c", url: "h2c://backend:50051", want: &http2.Transport{}},
		{name: "h3", url: "h3://backend:443", want: &http3.Transport{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTargetState(tt.url, 1)
			rt := f.TransportFor(s, req)
			switch tt.want.(type) {
			case *http.Transport:
				if _, ok := rt.(*http.Transport); !ok {
					t.Fatalf("expected *http.Transport, got %T", rt)
				}
			case *http2.Transport:
				if _, ok := rt.(*http2.Transport); !ok {
					t.Fatalf("expected *http2.Transport, got %T", rt)
				}
			case *http3.Transport:
				if _, ok := rt.(*http3.Transport); !ok {
					t.Fatalf("expected *http3.Transport, got %T", rt)
				}
			}
		})
	}
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
			{id: "tenant-a", matchHeader: "X-Tenant", matchHeaderValue: "a"},
			{id: "tenant-b", matchHeader: "X-Tenant", matchHeaderValue: "b"},
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
		err := writeProxyHeader(conn, "192.168.1.10:50000", backendAddr, gateonv1.ProxyProtocolVersion_PROXY_PROTOCOL_VERSION_V1)
		if err != nil {
			t.Fatalf("writeProxyHeader(v1) returned error: %v", err)
		}

		wantPrefix := "PROXY TCP4 192.168.1.10 10.10.10.10 50000 8080\r\n"
		if got := conn.String(); got != wantPrefix {
			t.Fatalf("unexpected PROXY v1 header\nwant: %q\n got: %q", wantPrefix, got)
		}
	})

	t.Run("v2", func(t *testing.T) {
		conn := &recordingConn{}
		err := writeProxyHeader(conn, "192.168.1.10:50000", backendAddr, gateonv1.ProxyProtocolVersion_PROXY_PROTOCOL_VERSION_V2)
		if err != nil {
			t.Fatalf("writeProxyHeader(v2) returned error: %v", err)
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
