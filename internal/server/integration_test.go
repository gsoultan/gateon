package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gateon/gateon/internal/api"
	"github.com/gateon/gateon/internal/auth"
	"github.com/gateon/gateon/internal/config"
	"github.com/gateon/gateon/internal/domain"
	"github.com/gateon/gateon/internal/middleware"
	"github.com/gateon/gateon/internal/server/handlers"
	"github.com/gateon/gateon/pkg/l4"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"google.golang.org/grpc"
)

func handlerDeps(s *Server) *handlers.Deps {
	l4Resolver := l4.NewResolver(s.RouteStore, s.ServiceStore)
	proxyInvalidator := NewServerProxyInvalidator(s, l4Resolver, s.RouteStore)
	mwFactory := middleware.NewFactory(s.RedisClient)
	return &handlers.Deps{
		RouteService:   domain.NewRouteService(s.RouteStore, proxyInvalidator),
		ServiceService: domain.NewServiceService(s.ServiceStore, s.RouteStore, proxyInvalidator),
		EpService:      domain.NewEntryPointService(s.EpStore),
		MwService:      domain.NewMiddlewareServiceWithOptions(s.MwStore, s.RouteStore, proxyInvalidator, mwFactory, middleware.WAFCacheInvalidator{}),
		TLSOptService:  domain.NewTLSOptionService(s.TLSOptStore),
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
	globalStore := s.GlobalStore

	svc := &gateonv1.Service{
		Id: "test-service", Name: "test-service",
		WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	}
	_ = s.ServiceStore.Update(context.Background(), svc)
	rt := &gateonv1.Route{
		Id: "test-route", ServiceId: svc.Id, Rule: "PathPrefix(`/test`)", Type: "http",
	}
	_ = s.RouteStore.Update(context.Background(), rt)

	grpcServer := grpc.NewServer()
	apiService := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteStore, Services: s.ServiceStore, Globals: globalStore,
		EntryPoints: s.EpStore, Middlewares: s.MwStore, TLSOptions: s.TLSOptStore,
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

func TestIntegration_ProxyWithIPFilterMiddleware(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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

	_ = s.ServiceStore.Update(context.Background(), &gateonv1.Service{
		Id: "svc", WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	})
	_ = s.MwStore.Update(context.Background(), &gateonv1.Middleware{
		Id: "ipfilter-1", Name: "ipfilter-1", Type: "ipfilter",
		Config: map[string]string{"allow_list": "127.0.0.1,::1", "deny_list": ""},
	})
	_ = s.RouteStore.Update(context.Background(), &gateonv1.Route{
		Id: "r1", ServiceId: "svc", Rule: "PathPrefix(`/api`)", Type: "http",
		Middlewares: []string{"ipfilter-1"},
	})

	apiSvc := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteStore, Services: s.ServiceStore, Globals: s.GlobalStore,
		EntryPoints: s.EpStore, Middlewares: s.MwStore, TLSOptions: s.TLSOptStore,
	})
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, apiSvc, handlerDeps(s))
	wrapped := grpcweb.WrapServer(grpc.NewServer())
	gatewayHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, wrapped, mux)
	})

	req := httptest.NewRequest("GET", "http://localhost/api/foo", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	gatewayHandler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("allowed IP: expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	req2 := httptest.NewRequest("GET", "http://localhost/api/foo", nil)
	req2.RemoteAddr = "10.0.0.1:12345"
	w2 := httptest.NewRecorder()
	gatewayHandler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("denied IP: expected 403, got %d", w2.Code)
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
	globalStore := s.GlobalStore

	_ = s.ServiceStore.Update(context.Background(), &gateonv1.Service{
		Id: "dynamic-service", Name: "dynamic-service",
		WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	})

	grpcServer := grpc.NewServer()
	apiService := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteStore, Services: s.ServiceStore, Globals: globalStore,
		EntryPoints: s.EpStore, Middlewares: s.MwStore, TLSOptions: s.TLSOptStore,
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
		Routes: s.RouteStore, Services: s.ServiceStore, Globals: s.GlobalStore,
		EntryPoints: s.EpStore, Middlewares: s.MwStore, TLSOptions: s.TLSOptStore,
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

func TestIntegration_RBAC_ViewerDeniedOnWrite(t *testing.T) {
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
	_ = s.ServiceStore.Update(context.Background(), &gateonv1.Service{
		Id: "svc", Name: "svc",
		WeightedTargets: []*gateonv1.Target{{Url: "http://localhost:9999", Weight: 1}},
	})

	apiService := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteStore, Services: s.ServiceStore, Globals: s.GlobalStore,
		EntryPoints: s.EpStore, Middlewares: s.MwStore, TLSOptions: s.TLSOptStore,
	})
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, apiService, handlerDeps(s))

	viewerClaims := &auth.Claims{ID: "v1", Username: "viewer", Role: auth.RoleViewer}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, viewerClaims)
	rt := &gateonv1.Route{Id: "rbac-route", ServiceId: "svc", Rule: "PathPrefix(`/rbac`)", Type: "http"}
	rtData, _ := handlers.ProtojsonOptions().Marshal(rt)

	req := httptest.NewRequest("PUT", "/v1/routes", strings.NewReader(string(rtData))).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("viewer PUT /v1/routes: expected 403, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "insufficient permissions") {
		t.Errorf("expected 'insufficient permissions' in body, got %s", w.Body.String())
	}
}

func TestIntegration_RBAC_ViewerAllowedOnRead(t *testing.T) {
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
		Routes: s.RouteStore, Services: s.ServiceStore, Globals: s.GlobalStore,
		EntryPoints: s.EpStore, Middlewares: s.MwStore, TLSOptions: s.TLSOptStore,
	})
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, apiService, handlerDeps(s))

	viewerClaims := &auth.Claims{ID: "v1", Username: "viewer", Role: auth.RoleViewer}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, viewerClaims)

	req := httptest.NewRequest("GET", "/v1/routes", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("viewer GET /v1/routes: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
}
