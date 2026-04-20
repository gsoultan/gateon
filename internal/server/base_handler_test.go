package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type mockRouteStore struct{}

func (m *mockRouteStore) List(ctx context.Context) []*gateonv1.Route {
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

func (m *mockRouteStore) Update(ctx context.Context, rt *gateonv1.Route) error {
	return nil
}

func (m *mockRouteStore) Delete(ctx context.Context, id string) error {
	return nil
}

type mockGlobalReg struct {
	config *gateonv1.GlobalConfig
}

func (m *mockGlobalReg) Get(ctx context.Context) *gateonv1.GlobalConfig {
	return m.config
}

func (m *mockGlobalReg) Update(ctx context.Context, config *gateonv1.GlobalConfig) error {
	m.config = config
	return nil
}

func (m *mockGlobalReg) ConfigFileExists() bool {
	return true
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

	handler := CreateBaseHandler(uiHandler, deps, nil, nil)

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
