package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gateon/gateon/internal/api"
	"github.com/gateon/gateon/internal/config"
	"github.com/gateon/gateon/internal/domain"
	"github.com/gateon/gateon/internal/server/handlers"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"google.golang.org/grpc"
)

func handlerDeps(s *Server) *handlers.Deps {
	return &handlers.Deps{
		RouteService:   domain.NewRouteService(s.RouteReg, s.InvalidateRouteProxy),
		ServiceService: domain.NewServiceService(s.ServiceReg, s.RouteReg, s.InvalidateRouteProxies),
		EpService:      domain.NewEntryPointService(s.EpReg),
		MwService:      domain.NewMiddlewareService(s.MwReg, s.RouteReg, s.InvalidateRouteProxies),
		TLSOptService:  domain.NewTLSOptionService(s.TLSOptReg),
		AuthManager:    s.AuthManager,
		Version:        s.Version,
		StartTime:      s.StartTime(),
	}
}

func TestIntegration_ProxyRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proxied-By", "MockBackend")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello from backend"))
	}))
	defer backend.Close()

	tmpDir := t.TempDir()
	s, err := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(tmpDir, "services.json"))),
		WithEntryPointRegistry(config.NewEntryPointRegistry(filepath.Join(tmpDir, "entrypoints.json"))),
		WithMiddlewareRegistry(config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))),
		WithTLSOptionRegistry(config.NewTLSOptionRegistry(filepath.Join(tmpDir, "tls_options.json"))),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(tmpDir, "global.json"))),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	globalReg := s.GlobalReg

	svc := &gateonv1.Service{
		Id: "test-service", Name: "test-service",
		WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	}
	_ = s.ServiceReg.Update(svc)
	rt := &gateonv1.Route{
		Id: "test-route", ServiceId: svc.Id, Rule: "PathPrefix(`/test`)", Type: "http",
	}
	_ = s.RouteReg.Update(rt)

	grpcServer := grpc.NewServer()
	apiService := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteReg, Services: s.ServiceReg, Globals: globalReg,
		EntryPoints: s.EpReg, Middlewares: s.MwReg, TLSOptions: s.TLSOptReg,
	})
	gateonv1.RegisterApiServiceServer(grpcServer, apiService)
	wrapped := grpcweb.WrapServer(grpcServer)
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, apiService, handlerDeps(s))

	gatewayHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, wrapped, mux)
	})

	req := httptest.NewRequest("GET", "http://localhost/test/foo", nil)
	w := httptest.NewRecorder()
	gatewayHandler.ServeHTTP(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v. Body: %s", resp.StatusCode, string(body))
	}
	if string(body) != "Hello from backend" {
		t.Errorf("expected body 'Hello from backend', got %q", string(body))
	}
	if resp.Header.Get("X-Proxied-By") != "MockBackend" {
		t.Errorf("expected X-Proxied-By: MockBackend, got %q", resp.Header.Get("X-Proxied-By"))
	}
}

func TestIntegration_RestApiAndProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Dynamic Backend"))
	}))
	defer backend.Close()

	tmpDir := t.TempDir()
	s, err := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(tmpDir, "services.json"))),
		WithEntryPointRegistry(config.NewEntryPointRegistry(filepath.Join(tmpDir, "entrypoints.json"))),
		WithMiddlewareRegistry(config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))),
		WithTLSOptionRegistry(config.NewTLSOptionRegistry(filepath.Join(tmpDir, "tls_options.json"))),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(tmpDir, "global.json"))),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	globalReg := s.GlobalReg

	_ = s.ServiceReg.Update(&gateonv1.Service{
		Id: "dynamic-service", Name: "dynamic-service",
		WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	})

	grpcServer := grpc.NewServer()
	apiService := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteReg, Services: s.ServiceReg, Globals: globalReg,
		EntryPoints: s.EpReg, Middlewares: s.MwReg, TLSOptions: s.TLSOptReg,
	})
	gateonv1.RegisterApiServiceServer(grpcServer, apiService)
	wrapped := grpcweb.WrapServer(grpcServer)
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, apiService, handlerDeps(s))

	gatewayHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, wrapped, mux)
	})

	rt := &gateonv1.Route{
		Id: "dynamic-route", ServiceId: "dynamic-service", Rule: "PathPrefix(`/dynamic`)", Type: "http",
	}
	rtData, _ := handlers.ProtojsonOptions().Marshal(rt)
	reqCreate := httptest.NewRequest("PUT", "/v1/routes", strings.NewReader(string(rtData)))
	reqCreate.Header.Set("Content-Type", "application/json")
	wCreate := httptest.NewRecorder()
	mux.ServeHTTP(wCreate, reqCreate)
	if wCreate.Code != http.StatusOK {
		t.Errorf("create route: %d %s", wCreate.Code, wCreate.Body.String())
	}

	reqProxy := httptest.NewRequest("GET", "http://localhost/dynamic/test", nil)
	wProxy := httptest.NewRecorder()
	gatewayHandler.ServeHTTP(wProxy, reqProxy)
	if wProxy.Code != http.StatusOK {
		t.Errorf("proxy: %d %s", wProxy.Code, wProxy.Body.String())
	}
	if wProxy.Body.String() != "Dynamic Backend" {
		t.Errorf("expected body 'Dynamic Backend', got %q", wProxy.Body.String())
	}
}

func TestIntegration_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(tmpDir, "services.json"))),
		WithEntryPointRegistry(config.NewEntryPointRegistry(filepath.Join(tmpDir, "entrypoints.json"))),
		WithMiddlewareRegistry(config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))),
		WithTLSOptionRegistry(config.NewTLSOptionRegistry(filepath.Join(tmpDir, "tls_options.json"))),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(tmpDir, "global.json"))),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	apiService := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteReg, Services: s.ServiceReg, Globals: s.GlobalReg,
		EntryPoints: s.EpReg, Middlewares: s.MwReg, TLSOptions: s.TLSOptReg,
	})
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, apiService, handlerDeps(s))
	wrapped := grpcweb.WrapServer(grpc.NewServer())
	gatewayHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, wrapped, mux)
	})

	req := httptest.NewRequest("GET", "http://localhost/not-found", nil)
	w := httptest.NewRecorder()
	gatewayHandler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}
