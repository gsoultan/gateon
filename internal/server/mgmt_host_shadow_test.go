// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/middleware/transform"
	"github.com/gsoultan/gateon/internal/server/handlers"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
	"google.golang.org/grpc"
)

// buildManagementHandler assembles the management entrypoint's handler chain the
// same way startSecureManagementServer does (EntryPoint(isMgmt=true) wrapping the
// base handler), with a real auth Manager, so an unauthenticated request is
// exercised against the actual authentication boundary.
func buildManagementHandler(t *testing.T, extraRoutes ...*gateonv1.Route) (http.Handler, *auth.Manager, string) {
	t.Helper()
	tmp := t.TempDir()
	mgr, err := auth.NewManager(filepath.Join(tmp, "auth.db"), "0123456789abcdef0123456789abcdef", logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.UpsertUser(&gateonv1.User{Username: "root", Password: "correct-horse", Role: auth.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	users, _, err := mgr.ListUsers(0, 10, "")
	if err != nil || len(users) == 0 {
		t.Fatalf("seed admin: %v", err)
	}
	adminID := users[0].Id

	s, err := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(tmp, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(tmp, "services.json"))),
		WithEntryPointRegistry(config.NewEntryPointRegistry(filepath.Join(tmp, "entrypoints.json"))),
		WithMiddlewareRegistry(config.NewMiddlewareRegistry(filepath.Join(tmp, "middlewares.json"))),
		WithTLSOptionRegistry(config.NewTLSOptionRegistry(filepath.Join(tmp, "tls_options.json"))),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(tmp, "global.json"))),
		WithAuthManager(mgr),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.GlobalStore.Update(t.Context(), &gateonv1.GlobalConfig{
		Auth: &gateonv1.AuthConfig{Enabled: true, PasetoSecret: "0123456789abcdef0123456789abcdef"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, rt := range extraRoutes {
		if err := s.RouteStore.Update(t.Context(), rt); err != nil {
			t.Fatal(err)
		}
	}

	apiSvc := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteStore, Services: s.ServiceStore, Globals: s.GlobalStore,
		EntryPoints: s.EpStore, Middlewares: s.MwStore, TLSOptions: s.TLSOptStore, Auth: s.AuthManager,
	})
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(NewGRPCRBACInterceptor()))
	gateonv1.RegisterApiServiceServer(grpcServer, apiSvc)
	internalAPI := transform.NewDefaultGRPCWebDetector(grpcServer)
	mux := http.NewServeMux()
	mux.Handle(gateonv1connect.NewApiServiceHandler(api.NewConnectHandler(apiSvc),
		connect.WithInterceptors(NewConnectRBACInterceptor())))
	handlers.RegisterRESTHandlers(mux, apiSvc, handlerDeps(s))
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, grpcServer, internalAPI, mux)
	})
	base := CreateBaseHandler(http.NotFoundHandler(), BaseHandlerDeps{
		ProxyHandler: proxyHandler, RouteStore: s.RouteStore, GlobalReg: s.GlobalStore,
		Auth: s.AuthManager, MgmtCORS: BuildManagementCORS(nil),
	}, internalAPI, mux)
	return middleware.EntryPoint("management", "management", true)(base), mgr, adminID
}

// A Host() proxy route matches every path on its host, including the management
// API. On the management entrypoint the base handler used to hand such a request
// straight to the proxy handler, skipping the authentication wrapper; the proxy
// handler then served the internal management mux with no credential. One
// ordinary vhost route therefore exposed the whole management API to an
// unauthenticated caller who set the Host header to that vhost.
func TestManagementHostRouteDoesNotBypassAuth(t *testing.T) {
	hostRoute := &gateonv1.Route{
		Id: "app", ServiceId: "app", Type: "http", Rule: "Host(`app.example.com`)",
	}
	h, mgr, adminID := buildManagementHandler(t, hostRoute)

	t.Run("read leaks global config with signing key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/v1/global", nil)
		req.RemoteAddr = "203.0.113.9:5555"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("GET /v1/global via Host route: status = %d, want 401; body: %s", rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "pasetoSecret") {
			t.Fatalf("unauthenticated response leaked the global config: %s", rr.Body.String())
		}
	})

	t.Run("write changes the admin password", func(t *testing.T) {
		body := `{"id":"` + adminID + `","password":"attacker-set"}`
		req := httptest.NewRequest(http.MethodPost, "http://app.example.com/v1/users/password", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.9:5555"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("POST /v1/users/password via Host route: status = %d, want 401; body: %s", rr.Code, rr.Body.String())
		}
		if _, _, err := mgr.Authenticate("root", "attacker-set"); err == nil {
			t.Fatal("unauthenticated request changed the admin password")
		}
	})

	t.Run("connect transport is reached without auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://app.example.com/gateon.v1.ApiService/GetGlobalConfig", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.9:5555"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			t.Fatalf("Connect GetGlobalConfig via Host route returned 200 without a credential; body: %s", rr.Body.String())
		}
	})
}

// The fix closes the bypass by routing management-API requests through the
// authentication wrapper rather than by denying them: with the same Host()
// route present, an admin who presents a valid session still reaches the API.
func TestManagementHostRouteStillAllowsAuthenticatedAdmin(t *testing.T) {
	hostRoute := &gateonv1.Route{
		Id: "app", ServiceId: "app", Type: "http", Rule: "Host(`app.example.com`)",
	}
	h, mgr, _ := buildManagementHandler(t, hostRoute)

	token, _, err := mgr.Authenticate("root", "correct-horse")
	if err != nil {
		t.Fatalf("authenticate admin: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/v1/global", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = "203.0.113.9:5555"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("authenticated admin GET /v1/global via Host route: status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "pasetoSecret") {
		t.Fatalf("authenticated admin should see the full global config, got: %s", rr.Body.String())
	}
}
