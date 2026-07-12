package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/router"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// mockTLSManager implements gtls.TLSManager for testing
type mockTLSManager struct {
	gtls.TLSManager
	cert *tls.Certificate
}

func (m *mockTLSManager) LoadCertificate(certFile, keyFile, caFile string) (*tls.Certificate, *x509.CertPool, error) {
	return m.cert, nil, nil
}
func (m *mockTLSManager) LoadCA(caFile string) (*x509.CertPool, error) { return nil, nil }
func (m *mockTLSManager) LoadCAData(caFile string) ([]byte, error)     { return nil, nil }
func (m *mockTLSManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.cert, nil
}

type mockRouteStoreVerify struct {
	config.RouteStore
	routes []*gateonv1.Route
}

func (m *mockRouteStoreVerify) List(ctx context.Context) []*gateonv1.Route {
	return m.routes
}

func (m *mockRouteStoreVerify) ListWildcards(ctx context.Context) []*gateonv1.Route {
	var res []*gateonv1.Route
	for _, r := range m.routes {
		h := router.HostFromRule(r.Rule)
		if h != "" && !router.RouteHostIsExact(h) {
			res = append(res, r)
		} else if h == "" {
			res = append(res, r)
		}
	}
	return res
}

func (m *mockRouteStoreVerify) GetByHost(host string) []*gateonv1.Route {
	var res []*gateonv1.Route
	for _, r := range m.routes {
		h := router.HostFromRule(r.Rule)
		if h != "" && router.RouteHostIsExact(h) && config.HostMatches(h, host) {
			res = append(res, r)
		}
	}
	return res
}

type mockGlobalRegVerify struct {
	config.GlobalConfigStore
	config    *gateonv1.GlobalConfig
	certIndex map[string]*gateonv1.Certificate
}

func (m *mockGlobalRegVerify) Get(ctx context.Context) *gateonv1.GlobalConfig {
	return m.config
}

func (m *mockGlobalRegVerify) GetCertificate(id string) (*gateonv1.Certificate, bool) {
	c, ok := m.certIndex[id]
	return c, ok
}

func TestOPTIONSPreflightMatching(t *testing.T) {
	routes := []*gateonv1.Route{
		{
			Id:   "grpc-backtick",
			Rule: "Host(`grpc.example.com`) && PathPrefix(`/service/`) && Methods(`POST`)",
			Type: "grpc",
		},
		{
			Id:   "grpc-quote",
			Rule: "Host(\"grpc.quote.com\") && PathPrefix(\"/service/\") && Methods(\"POST\")",
			Type: "grpc",
		},
		{
			Id:   "http-get",
			Rule: "Host(`www.example.com`) && Path(`/index.html`) && Methods(`GET`) && Headers(`X-Custom`, `val`)",
			Type: "http",
		},
	}

	tests := []struct {
		name     string
		method   string
		host     string
		path     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "Valid gRPC POST (backtick)",
			method:   "POST",
			host:     "grpc.example.com",
			path:     "/service/Method",
			expected: "grpc-backtick",
		},
		{
			name:   "gRPC OPTIONS preflight (backtick)",
			method: "OPTIONS",
			host:   "grpc.example.com",
			path:   "/service/Method",
			headers: map[string]string{
				"Access-Control-Request-Method": "POST",
				"Origin":                        "https://app.example.com",
			},
			expected: "grpc-backtick",
		},
		{
			name:     "Valid gRPC POST (quote)",
			method:   "POST",
			host:     "grpc.quote.com",
			path:     "/service/Method",
			expected: "grpc-quote",
		},
		{
			name:   "gRPC OPTIONS preflight (quote)",
			method: "OPTIONS",
			host:   "grpc.quote.com",
			path:   "/service/Method",
			headers: map[string]string{
				"Access-Control-Request-Method": "POST",
				"Origin":                        "https://app.quote.com",
			},
			expected: "grpc-quote",
		},
		{
			name:   "Valid HTTP GET",
			method: "GET",
			host:   "www.example.com",
			path:   "/index.html",
			headers: map[string]string{
				"X-Custom": "val",
			},
			expected: "http-get",
		},
		{
			name:   "HTTP OPTIONS preflight (skips header check)",
			method: "OPTIONS",
			host:   "www.example.com",
			path:   "/index.html",
			headers: map[string]string{
				"Access-Control-Request-Method": "GET",
				"Origin":                        "https://app.example.com",
			},
			expected: "http-get",
		},
		{
			name:     "Method mismatch",
			method:   "GET",
			host:     "grpc.example.com",
			path:     "/service/Method",
			expected: "",
		},
		{
			name:   "Header mismatch",
			method: "GET",
			host:   "www.example.com",
			path:   "/index.html",
			headers: map[string]string{
				"X-Custom": "wrong",
			},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, "https://"+tc.host+tc.path, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			got := router.SelectRouteFromSlice(req, routes)
			if tc.expected == "" {
				if got != nil {
					t.Errorf("Expected no match, got %s", got.Id)
				}
			} else {
				if got == nil || got.Id != tc.expected {
					t.Errorf("Expected match %s, got %v", tc.expected, got)
				}
			}
		})
	}
}

func TestConcurrentSNIMatchingStability(t *testing.T) {
	// Setup a mock environment
	routes := []*gateonv1.Route{
		{
			Id:   "r1",
			Rule: "Host(`a.com`) && Path(`/`) && Methods(`GET`)",
			Tls:  &gateonv1.RouteTLSConfig{CertificateIds: []string{"c1"}},
		},
		{
			Id:   "r2",
			Rule: "Host(`b.com`) && Path(`/`) && Methods(`GET`)",
			Tls:  &gateonv1.RouteTLSConfig{CertificateIds: []string{"c2"}},
		},
		{
			Id:   "w1",
			Rule: "Host(`*.wild.com`) && Path(`/`) && Methods(`GET`)",
			Tls:  &gateonv1.RouteTLSConfig{CertificateIds: []string{"cw"}},
		},
	}

	rs := &mockRouteStoreVerify{routes: routes}
	gs := &mockGlobalRegVerify{
		config: &gateonv1.GlobalConfig{
			Tls: &gateonv1.TlsConfig{
				Certificates: []*gateonv1.Certificate{
					{Id: "c1", CertFile: "c1.crt", KeyFile: "c1.key"},
					{Id: "c2", CertFile: "c2.crt", KeyFile: "c2.key"},
					{Id: "cw", CertFile: "cw.crt", KeyFile: "cw.key"},
				},
			},
		},
	}
	// Rebuild index manually for mock
	gs.certIndex = make(map[string]*gateonv1.Certificate)
	for _, c := range gs.config.Tls.Certificates {
		gs.certIndex[c.Id] = c
	}

	deps := SNIDeps{
		RouteStore:  rs,
		GlobalStore: gs,
		TLSOptStore: &mockTLSOptStore{},
	}

	cfg := &tls.Config{}
	// Generate a dummy certificate
	cert := tls.Certificate{}
	mgr := &mockTLSManager{cert: &cert}

	SetupSNI(cfg, mgr, deps)

	if cfg.GetConfigForClient == nil {
		t.Fatal("GetConfigForClient not set")
	}

	const workers = 50
	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(workers)

	// Simulate concurrent handshakes from same IP (represented by a dummy net.Conn)
	dummyConn := &mockConn{remoteAddr: "1.2.3.4:1234"}

	for i := 0; i < workers; i++ {
		go func(id int) {
			defer wg.Done()
			var hosts = []string{"a.com", "b.com", "sub.wild.com", "unknown.com", ""}
			host := hosts[id%len(hosts)]

			for j := 0; j < iterations; j++ {
				_, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{
					ServerName: host,
					Conn:       dummyConn,
				})
				if err != nil {
					t.Errorf("worker %d failed for host %q: %v", id, host, err)
					return
				}
			}
		}(i)
	}

	wg.Wait()
}

type mockConn struct {
	net.Conn
	remoteAddr string
}

func (c *mockConn) RemoteAddr() net.Addr {
	return &mockAddr{addr: c.remoteAddr}
}

type mockAddr struct {
	net.Addr
	addr string
}

func (a *mockAddr) String() string  { return a.addr }
func (a *mockAddr) Network() string { return "tcp" }

type mockTLSOptStore struct {
	config.TLSOptionStore
}

func (m *mockTLSOptStore) Get(ctx context.Context, id string) (*gateonv1.TLSOption, bool) {
	return nil, false
}
