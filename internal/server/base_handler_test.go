// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/rs/cors"
	"github.com/stretchr/testify/assert"
)

type mockRouteStore struct{}

func (m *mockRouteStore) List(ctx context.Context) []*gateonv1.Route {
	return nil
}

func (m *mockRouteStore) ListWildcards(ctx context.Context) []*gateonv1.Route {
	return nil
}

func (m *mockRouteStore) ListPaginated(ctx context.Context, page, pageSize int32, search string, filter *config.RouteFilter) ([]*gateonv1.Route, int32) {
	return nil, 0
}

func (m *mockRouteStore) All(ctx context.Context) map[string]*gateonv1.Route {
	return nil
}

func (m *mockRouteStore) Get(ctx context.Context, id string) (*gateonv1.Route, bool) {
	return nil, false
}

func (m *mockRouteStore) GetByHost(host string) []*gateonv1.Route {
	return nil
}

func (m *mockRouteStore) Update(ctx context.Context, rt *gateonv1.Route) error {
	return nil
}

func (m *mockRouteStore) Delete(ctx context.Context, id string) error {
	return nil
}

func (m *mockRouteStore) GetTrieByHost(host string) (*config.PathTrie, []*gateonv1.Route) {
	return nil, nil
}

func (m *mockRouteStore) GetWildcardTrie() (*config.PathTrie, []*gateonv1.Route) {
	return nil, nil
}

type mockGlobalReg struct {
	config *gateonv1.GlobalConfig
}

func (m *mockGlobalReg) Get(ctx context.Context) *gateonv1.GlobalConfig {
	return m.config
}

func (m *mockGlobalReg) GetCertificate(id string) (*gateonv1.Certificate, bool) {
	if m.config != nil && m.config.Tls != nil {
		for _, c := range m.config.Tls.Certificates {
			if c.Id == id {
				return c, true
			}
		}
	}
	return nil, false
}

func (m *mockGlobalReg) Update(ctx context.Context, config *gateonv1.GlobalConfig) error {
	m.config = config
	return nil
}

func (m *mockGlobalReg) ConfigFileExists() bool {
	return true
}

type mockRouteStoreWithRoutes struct {
	mockRouteStore
	routes []*gateonv1.Route
}

func (m *mockRouteStoreWithRoutes) List(ctx context.Context) []*gateonv1.Route {
	return m.routes
}

func (m *mockRouteStoreWithRoutes) GetTrieByHost(host string) (*config.PathTrie, []*gateonv1.Route) {
	return nil, m.routes
}

func (m *mockRouteStoreWithRoutes) GetWildcardTrie() (*config.PathTrie, []*gateonv1.Route) {
	return nil, m.routes
}

func TestCreateBaseHandler_CORSBypassProxy(t *testing.T) {
	// 1. Setup mocks
	// Define a route for /v1/invoices
	rt := &gateonv1.Route{
		Id:   "invoice-route",
		Rule: "PathPrefix(`/v1/invoices`)",
	}
	routeStore := &mockRouteStoreWithRoutes{routes: []*gateonv1.Route{rt}}
	globalStore := &mockGlobalReg{config: &gateonv1.GlobalConfig{}}

	// 2. Setup MgmtCORS with a restricted origin
	mgmtCors := cors.New(cors.Options{
		AllowedOrigins: []string{"https://mgmt.allowed.id"},
	})

	// Proxy handler that adds its own CORS header to simulate route CORS middleware
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://proxy.allowed.id")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied"))
	})

	deps := BaseHandlerDeps{
		ProxyHandler: proxyHandler,
		RouteStore:   routeStore,
		GlobalReg:    globalStore,
		MgmtCORS:     mgmtCors,
	}

	handler := CreateBaseHandler(http.NotFoundHandler(), deps, nil, http.NewServeMux())

	// 3. Test preflight request from a DIFFERENT origin (the one that was previously blocked)
	req := httptest.NewRequest("OPTIONS", "https://api.mulford.id/v1/invoices", nil)
	req.Header.Set("Origin", "https://cms.mulford.id")
	req.Header.Set("Access-Control-Request-Method", "GET")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// In the fixed implementation, MgmtCORS is bypassed for proxy routes.
	// Since our mock proxyHandler adds the header, it should be present.
	// If MgmtCORS was still intercepting, it would return 204 with no headers (because origin mismatch).
	assert.Equal(t, "https://proxy.allowed.id", w.Header().Get("Access-Control-Allow-Origin"), "Proxy CORS should NOT be shadowed by MgmtCORS")
}

func TestCreateBaseHandler_CORSBypassGRPC(t *testing.T) {
	// 1. Setup mocks
	// Define a route for gRPC
	rt := &gateonv1.Route{
		Id:   "grpc-route",
		Rule: "PathPrefix(`/poseidon.employee.EmployeeService/`)",
	}
	routeStore := &mockRouteStoreWithRoutes{routes: []*gateonv1.Route{rt}}
	globalStore := &mockGlobalReg{config: &gateonv1.GlobalConfig{}}

	// 2. Setup MgmtCORS with a restricted origin
	mgmtCors := cors.New(cors.Options{
		AllowedOrigins: []string{"https://mgmt.allowed.id"},
	})

	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://cms.mulford.id")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied-grpc"))
	})

	deps := BaseHandlerDeps{
		ProxyHandler: proxyHandler,
		RouteStore:   routeStore,
		GlobalReg:    globalStore,
		MgmtCORS:     mgmtCors,
	}

	handler := CreateBaseHandler(http.NotFoundHandler(), deps, nil, http.NewServeMux())

	// 3. Test gRPC-web preflight request
	req := httptest.NewRequest("OPTIONS", "https://grpc.mulford.id/poseidon.employee.EmployeeService/SignIn", nil)
	req.Header.Set("Origin", "https://cms.mulford.id")
	req.Header.Set("Access-Control-Request-Method", "POST")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "https://cms.mulford.id", w.Header().Get("Access-Control-Allow-Origin"), "gRPC Proxy CORS should NOT be shadowed by MgmtCORS")
}

func TestCreateBaseHandler_CORSBypassHostSpecific(t *testing.T) {
	// 1. Setup mocks
	// Define a route for /v1/invoices WITH a Host rule
	rt := &gateonv1.Route{
		Id:   "invoice-route",
		Rule: "Host(`api.mulford.id`) && PathPrefix(`/v1/invoices`)",
	}
	routeStore := &mockRouteStoreWithRoutes{routes: []*gateonv1.Route{rt}}
	globalStore := &mockGlobalReg{config: &gateonv1.GlobalConfig{}}

	// 2. Setup MgmtCORS with a restricted origin
	mgmtCors := cors.New(cors.Options{
		AllowedOrigins: []string{"https://mgmt.allowed.id"},
	})

	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://cms.mulford.id")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied"))
	})

	deps := BaseHandlerDeps{
		ProxyHandler: proxyHandler,
		RouteStore:   routeStore,
		GlobalReg:    globalStore,
		MgmtCORS:     mgmtCors,
	}

	handler := CreateBaseHandler(http.NotFoundHandler(), deps, nil, http.NewServeMux())

	// 3. Test preflight request for the proxy route
	// We use the management entrypoint ID to simulate the most difficult case
	req := httptest.NewRequest("OPTIONS", "https://api.mulford.id/v1/invoices", nil)
	req.Header.Set("Origin", "https://cms.mulford.id")
	req.Header.Set("Access-Control-Request-Method", "GET")

	// Inject management entrypoint ID
	ctx := context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "management")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Even on management entrypoint, because the route has a Host rule matching the request,
	// it should bypass MgmtCORS and be handled by the proxy.
	assert.Equal(t, "https://cms.mulford.id", w.Header().Get("Access-Control-Allow-Origin"), "Host-specific route should bypass MgmtCORS even on management entrypoint")
}

func TestCreateBaseHandler_Security(t *testing.T) {
	uiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("UI"))
	})
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Proxy"))
	})
	globalReg := &mockGlobalReg{
		config: &gateonv1.GlobalConfig{
			Management: &gateonv1.ManagementConfig{
				AllowPublicManagement: false,
			},
		},
	}
	deps := BaseHandlerDeps{
		ProxyHandler: proxyHandler,
		RouteStore:   &mockRouteStore{},
		GlobalReg:    globalReg,
	}

	tests := []struct {
		name           string
		path           string
		entrypoint     string
		host           string
		allowedHosts   []string
		envAllowed     bool
		expectedStatus int
	}{
		{
			name:           "Public entrypoint - setup - 404",
			path:           "/v1/setup/required",
			entrypoint:     "http-80",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Management entrypoint - setup - 200",
			path:           "/v1/setup/required",
			entrypoint:     "management",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Public entrypoint - health - 200",
			path:           "/healthz",
			entrypoint:     "http-80",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Public entrypoint - metrics - 404",
			path:           "/metrics",
			entrypoint:     "http-80",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Public entrypoint - setup - Env Allowed - 200",
			path:           "/v1/setup/required",
			entrypoint:     "http-80",
			envAllowed:     true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Public entrypoint - Allowed Host - 200",
			path:           "/v1/setup/required",
			entrypoint:     "http-80",
			host:           "admin.example.com",
			allowedHosts:   []string{"admin.example.com"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Public entrypoint - Allowed Host with Port - 200",
			path:           "/v1/setup/required",
			entrypoint:     "http-80",
			host:           "admin.example.com:8080",
			allowedHosts:   []string{"admin.example.com"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Public entrypoint - Wrong Host - 404",
			path:           "/v1/setup/required",
			entrypoint:     "http-80",
			host:           "hacker.com",
			allowedHosts:   []string{"admin.example.com"},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			globalReg.config.Management.AllowedHosts = tt.allowedHosts
			if tt.envAllowed {
				t.Setenv("GATEON_ALLOW_PUBLIC_MANAGEMENT", "true")
			} else {
				t.Setenv("GATEON_ALLOW_PUBLIC_MANAGEMENT", "false")
			}
			handler := CreateBaseHandler(uiHandler, deps, nil, nil)
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.host != "" {
				req.Host = tt.host
			}
			ctx := context.WithValue(req.Context(), middleware.EntryPointIDContextKey, tt.entrypoint)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestBaseHandler_BodyLimit(t *testing.T) {
	uiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	deps := BaseHandlerDeps{
		ProxyHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		RouteStore:   &mockRouteStore{},
		GlobalReg: &mockGlobalReg{
			config: &gateonv1.GlobalConfig{
				Management: &gateonv1.ManagementConfig{
					AllowPublicManagement: true,
				},
			},
		},
	}

	handler := CreateBaseHandler(uiHandler, deps, nil, nil)

	t.Run("UnderLimit", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), 1024) // 1KB
		req := httptest.NewRequest("POST", "/any", bytes.NewReader(body))
		ctx := context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "management")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("GeoIP_OverDefaultLimit", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), 11*1024*1024) // 11MB
		req := httptest.NewRequest("POST", "/v1/geoip/upload", bytes.NewReader(body))
		ctx := context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "management")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		// Should be 200 (or at least not 413)
		if rr.Code == http.StatusRequestEntityTooLarge {
			t.Errorf("expected not 413, got %d", rr.Code)
		}
	})

	t.Run("Other_OverDefaultLimit", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), 11*1024*1024) // 11MB
		req := httptest.NewRequest("POST", "/not-v1", bytes.NewReader(body))
		ctx := context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "management")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("expected 413, got %d", rr.Code)
		}
	})
}

func TestBaseHandler_ManagementAPIPriority(t *testing.T) {
	uiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("UI"))
	})
	// Simulate Server.HandleProxyOrLocal behavior:
	// If it's a management API path on an allowed management context, route to internal API.
	// Otherwise, route to proxied target.
	proxyOrLocalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowPublic := isPublicManagementAllowed(r, "http-80", &mockGlobalReg{
			config: &gateonv1.GlobalConfig{
				Management: &gateonv1.ManagementConfig{
					AllowPublicManagement: true,
				},
			},
		})
		isMgmtAPI := allowPublic && isGateonManagementAPIPath(r.URL.Path)
		if isMgmtAPI {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Internal API"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Proxied Target"))
	})

	deps := BaseHandlerDeps{
		ProxyHandler: proxyOrLocalHandler,
		RouteStore:   &mockRouteStore{},
		GlobalReg: &mockGlobalReg{
			config: &gateonv1.GlobalConfig{
				Management: &gateonv1.ManagementConfig{
					AllowPublicManagement: true,
				},
			},
		},
	}

	handler := CreateBaseHandler(uiHandler, deps, nil, nil)

	paths := []string{
		"/v1/status",
		"/v1/agg-stats",
		"/v1/path-stats",
		"/v1/global",
		"/v1/logs",
		"/v1/diag/sys",
		"/v1/security/posture",
		"/gateon.v1.ApiService/ListSecurityThreats",
	}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest("GET", p, nil)
			ctx := context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "http-80")
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("expected 200 for %s, got %d", p, rr.Code)
			}
			body := rr.Body.String()
			if body != "Internal API" {
				t.Errorf("expected Internal API for %s, but got %s", p, body)
			}
		})
	}
}
