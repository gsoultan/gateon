package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/server/handlers"
	"github.com/gsoultan/gateon/pkg/l4"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"google.golang.org/grpc"
)

func handlerDeps(s *Server) *handlers.Deps {
	l4Resolver := l4.NewResolver(s.RouteStore, s.ServiceStore)
	proxyInvalidator := NewServerProxyInvalidator(s, l4Resolver, s.RouteStore)
	mwFactory := middleware.NewFactory(s.RedisClient, s.GlobalStore)
	return &handlers.Deps{
		RouteService:   domain.NewRouteService(s.RouteStore, proxyInvalidator),
		ServiceService: domain.NewServiceService(s.ServiceStore, s.RouteStore, proxyInvalidator),
		EpService:      domain.NewEntryPointService(s.EpStore),
		MwService:      domain.NewMiddlewareServiceWithOptions(s.MwStore, s.RouteStore, proxyInvalidator, mwFactory, middleware.WAFCacheInvalidator{}),
		TLSOptService:  domain.NewTLSOptionService(s.TLSOptStore, s.RouteStore, proxyInvalidator),
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
		TLSManager: s.TLSManager,
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
		TLSManager: s.TLSManager,
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
		TLSManager: s.TLSManager,
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

func TestIntegration_ProxyWithOAuth2IntrospectionMiddleware(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()

	// Mock OAuth 2.0 introspection endpoint (RFC 7662)
	introServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		token := r.FormValue("token")
		if token == "" {
			token = r.PostFormValue("token")
		}
		if token == "valid-token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"active":true,"sub":"user123","scope":"read"}`))
		} else {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"active":false}`))
		}
	}))
	defer introServer.Close()

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
		WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	})
	_ = s.MwStore.Update(context.Background(), &gateonv1.Middleware{
		Id: "oauth2-auth", Name: "oauth2-auth", Type: "auth",
		Config: map[string]string{
			"type":              "oauth2",
			"introspection_url": introServer.URL,
			"client_id":         "test-client",
			"client_secret":     "test-secret",
		},
	})
	_ = s.RouteStore.Update(context.Background(), &gateonv1.Route{
		Id: "r1", ServiceId: "svc", Rule: "PathPrefix(`/api`)", Type: "http",
		Middlewares: []string{"oauth2-auth"},
	})

	apiSvc := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteStore, Services: s.ServiceStore, Globals: s.GlobalStore,
		EntryPoints: s.EpStore, Middlewares: s.MwStore, TLSOptions: s.TLSOptStore,
		TLSManager: s.TLSManager,
	})
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, apiSvc, handlerDeps(s))
	wrapped := grpcweb.WrapServer(grpc.NewServer())
	gatewayHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, wrapped, mux)
	})

	// Valid token -> backend
	req := httptest.NewRequest("GET", "http://localhost/api/foo", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	gatewayHandler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("valid token: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if w.Body.String() != "backend-ok" {
		t.Errorf("valid token: expected backend-ok, got %q", w.Body.String())
	}

	// Invalid token -> 401
	req2 := httptest.NewRequest("GET", "http://localhost/api/foo", nil)
	req2.Header.Set("Authorization", "Bearer invalid-token")
	w2 := httptest.NewRecorder()
	gatewayHandler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("invalid token: expected 401, got %d body=%s", w2.Code, w2.Body.String())
	}

	// No token -> 401
	req3 := httptest.NewRequest("GET", "http://localhost/api/foo", nil)
	w3 := httptest.NewRecorder()
	gatewayHandler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusUnauthorized {
		t.Errorf("no token: expected 401, got %d", w3.Code)
	}
}

func TestIntegration_ProxyWithOIDCMiddleware(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()

	// Mock OIDC discovery + JWKS (RS256 test key from jwt.io)
	oidcMux := http.NewServeMux()
	oidcServer := httptest.NewServer(oidcMux)
	defer oidcServer.Close()
	oidcMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + oidcServer.URL + `","jwks_uri":"` + oidcServer.URL + `/jwks"}`))
	})
	oidcMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"test","use":"sig","alg":"RS256","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}]}`))
	})
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
		WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	})
	_ = s.MwStore.Update(context.Background(), &gateonv1.Middleware{
		Id: "oidc-auth", Name: "oidc-auth", Type: "auth",
		Config: map[string]string{
			"type":     "oidc",
			"issuer":   oidcServer.URL,
			"audience": "api",
		},
	})
	_ = s.RouteStore.Update(context.Background(), &gateonv1.Route{
		Id: "r1", ServiceId: "svc", Rule: "PathPrefix(`/api`)", Type: "http",
		Middlewares: []string{"oidc-auth"},
	})

	apiSvc := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteStore, Services: s.ServiceStore, Globals: s.GlobalStore,
		EntryPoints: s.EpStore, Middlewares: s.MwStore, TLSOptions: s.TLSOptStore,
		TLSManager: s.TLSManager,
	})
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, apiSvc, handlerDeps(s))
	wrapped := grpcweb.WrapServer(grpc.NewServer())
	gatewayHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, wrapped, mux)
	})

	// Without token -> 401 (proves OIDC middleware is in chain)
	req := httptest.NewRequest("GET", "http://localhost/api/foo", nil)
	w := httptest.NewRecorder()
	gatewayHandler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: expected 401, got %d body=%s", w.Code, w.Body.String())
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
