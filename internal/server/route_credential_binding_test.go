// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/authz/routebind"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/route"
	"github.com/gsoultan/gateon/internal/domain/service"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/server/handlers"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// routeAPI serves the route and service API the way run.go mounts it -- REST on
// the mux and gRPC by content type, both behind the same claims and the gRPC
// RBAC interceptor -- to a caller of one role, over real route/service/
// middleware stores wired with the ADR 0038 binding guard.
type routeAPI struct {
	url    string
	http   *http.Client
	grpc     gateonv1.ApiServiceClient
	routes   *config.RouteRegistry
	services *config.ServiceRegistry
}

func newRouteAPI(t *testing.T, role string) *routeAPI {
	t.Helper()
	dir := t.TempDir()
	reg := config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	seedBindingFixtures(t, reg, services)

	guard := routebind.NewGuard(routes, services, reg)
	svc := &api.ApiService{Middlewares: reg, Routes: routes, Services: services}
	deps := &handlers.Deps{
		RouteService:   route.NewService(routes, mwNoopInvalidator{}, logger.Default(), guard),
		ServiceService: service.NewService(services, routes, mwNoopInvalidator{}, logger.Default(), guard),
	}

	mux := http.NewServeMux()
	mux.Handle(apiConnectHandler(svc))
	handlers.RegisterRESTHandlers(mux, svc, deps)
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(NewGRPCRBACInterceptor()))
	gateonv1.RegisterApiServiceServer(grpcServer, svc)
	t.Cleanup(grpcServer.Stop)
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	caller := &auth.Claims{ID: role + "-1", Username: role, Role: role}
	srv := httptest.NewUnstartedServer(withClaims(dispatch, caller))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	conn, err := grpc.NewClient(strings.TrimPrefix(srv.URL, "https://"),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &routeAPI{url: srv.URL, http: srv.Client(), grpc: gateonv1.NewApiServiceClient(conn), routes: routes, services: services}
}

// seedBindingFixtures stores the middlewares and services the tests bind to: a
// headers middleware that injects Authorization, a rewrite middleware that
// injects an api-key query parameter, a plain headers middleware, and two
// services -- one an admin would legitimately target and one the caller runs.
func seedBindingFixtures(t *testing.T, reg *config.MiddlewareRegistry, services *config.ServiceRegistry) {
	t.Helper()
	ctx := context.Background()
	mws := []*gateonv1.Middleware{
		{Id: "cred-hdr", Name: "cred-hdr", Type: "headers",
			Config: map[string]string{"set_request_Authorization": "Bearer sk-admin-secret"}},
		{Id: "cred-qry", Name: "cred-qry", Type: "rewrite",
			Config: map[string]string{"query_api_key": "adminkey"}},
		{Id: "plain", Name: "plain", Type: "headers",
			Config: map[string]string{"set_request_X-Trace-Id": "abc"}},
	}
	for _, m := range mws {
		if err := reg.Update(ctx, m); err != nil {
			t.Fatalf("seed middleware %s: %v", m.Id, err)
		}
	}
	svcs := []*gateonv1.Service{
		{Id: "svc-legit", Name: "svc-legit", BackendType: "http",
			WeightedTargets: []*gateonv1.Target{{Url: "http://legit.internal:8080", Weight: 1}}},
		{Id: "svc-evil", Name: "svc-evil", BackendType: "http",
			WeightedTargets: []*gateonv1.Target{{Url: "http://attacker.example:9090", Weight: 1}}},
	}
	for _, s := range svcs {
		if err := services.Update(ctx, s); err != nil {
			t.Fatalf("seed service %s: %v", s.Id, err)
		}
	}
}

func credentialRoute(id, serviceID string, mws ...string) *gateonv1.Route {
	return &gateonv1.Route{
		Id: id, Name: id, Type: "http", Rule: "Host(`" + id + ".test`)",
		Middlewares: mws, ServiceId: serviceID,
	}
}

func (a *routeAPI) putRouteREST(t *testing.T, rt *gateonv1.Route) int {
	t.Helper()
	body, err := protojson.Marshal(rt)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, a.url+"/v1/routes", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func (a *routeAPI) putServiceREST(t *testing.T, svc *gateonv1.Service) int {
	t.Helper()
	body, err := protojson.Marshal(svc)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, a.url+"/v1/services", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func (a *routeAPI) hasRoute(id string) bool {
	_, ok := a.routes.Get(context.Background(), id)
	return ok
}

// TestOperatorCannotBindCredentialMiddleware is the escalation ADR 0038 closes:
// an operator who may write routes attaches an existing, admin-configured
// credential-injecting middleware to a route whose service they control and
// reads the stored Authorization or api-key at their own backend. The bind is
// refused on REST and over gRPC -- the transport that historically slipped past
// authorization -- and the route is not stored.
func TestOperatorCannotBindCredentialMiddleware(t *testing.T) {
	for _, mw := range []string{"cred-hdr", "cred-qry"} {
		t.Run("REST/"+mw, func(t *testing.T) {
			a := newRouteAPI(t, auth.RoleOperator)
			rt := credentialRoute("op-bind-"+mw, "svc-evil", mw)
			if code := a.putRouteREST(t, rt); code != http.StatusForbidden {
				t.Fatalf("PUT /v1/routes as operator binding %s: got %d, want 403", mw, code)
			}
			if a.hasRoute(rt.Id) {
				t.Fatalf("route %s was stored despite the refusal", rt.Id)
			}
		})
		t.Run("gRPC/"+mw, func(t *testing.T) {
			a := newRouteAPI(t, auth.RoleOperator)
			rt := credentialRoute("op-grpc-"+mw, "svc-evil", mw)
			_, err := a.grpc.UpdateRoute(context.Background(), &gateonv1.UpdateRouteRequest{Route: rt})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("gRPC UpdateRoute as operator binding %s: got %v, want PermissionDenied", mw, err)
			}
			if a.hasRoute(rt.Id) {
				t.Fatalf("route %s was stored despite the refusal", rt.Id)
			}
		})
	}
}

// TestOperatorMayManageOrdinaryRoute proves the rule does not break an operator
// managing a route that carries no credential-injecting middleware: create and
// update both succeed.
func TestOperatorMayManageOrdinaryRoute(t *testing.T) {
	a := newRouteAPI(t, auth.RoleOperator)
	rt := credentialRoute("ordinary", "svc-legit", "plain")
	if code := a.putRouteREST(t, rt); code != http.StatusOK {
		t.Fatalf("PUT /v1/routes as operator for an ordinary route: got %d, want 200", code)
	}
	if !a.hasRoute(rt.Id) {
		t.Fatal("ordinary route was not stored")
	}
	rt.Priority = 5
	if code := a.putRouteREST(t, rt); code != http.StatusOK {
		t.Fatalf("re-PUT /v1/routes as operator for an ordinary route: got %d, want 200", code)
	}
}

// TestOperatorMayKeepAdminBindingButNotRepoint: an operator may edit a route an
// admin bound a credential middleware to, as long as the change does not repoint
// it -- but changing its service to one the operator controls is refused.
func TestOperatorMayKeepAdminBindingButNotRepoint(t *testing.T) {
	a := newRouteAPI(t, auth.RoleOperator)
	// The admin's pre-existing binding, seeded directly into the store.
	admin := credentialRoute("admin-cred", "svc-legit", "cred-hdr")
	if err := a.routes.Update(context.Background(), admin); err != nil {
		t.Fatal(err)
	}

	// Keeping the binding and service, editing something else, is allowed.
	kept := credentialRoute("admin-cred", "svc-legit", "cred-hdr")
	kept.Priority = 9
	if code := a.putRouteREST(t, kept); code != http.StatusOK {
		t.Fatalf("operator editing an unchanged admin binding: got %d, want 200", code)
	}

	// Repointing that route to the operator's own service is refused.
	repoint := credentialRoute("admin-cred", "svc-evil", "cred-hdr")
	if code := a.putRouteREST(t, repoint); code != http.StatusForbidden {
		t.Fatalf("operator repointing a credential route: got %d, want 403", code)
	}
	if got, _ := a.routes.Get(context.Background(), "admin-cred"); got.GetServiceId() != "svc-legit" {
		t.Fatalf("route was repointed to %q despite the refusal", got.GetServiceId())
	}
}

// TestOperatorCannotRepointCredentialService is the other end of the same
// escalation: rather than touch the route, the operator repoints the service it
// backs onto their own address. Refused on REST and gRPC.
func TestOperatorCannotRepointCredentialService(t *testing.T) {
	setup := func(t *testing.T) *routeAPI {
		a := newRouteAPI(t, auth.RoleOperator)
		admin := credentialRoute("admin-cred", "svc-legit", "cred-hdr")
		if err := a.routes.Update(context.Background(), admin); err != nil {
			t.Fatal(err)
		}
		return a
	}
	evil := &gateonv1.Service{Id: "svc-legit", Name: "svc-legit", BackendType: "http",
		WeightedTargets: []*gateonv1.Target{{Url: "http://attacker.example:9090", Weight: 1}}}

	t.Run("REST", func(t *testing.T) {
		a := setup(t)
		if code := a.putServiceREST(t, evil); code != http.StatusForbidden {
			t.Fatalf("operator repointing a credential-backed service: got %d, want 403", code)
		}
	})
	t.Run("gRPC", func(t *testing.T) {
		a := setup(t)
		_, err := a.grpc.UpdateService(context.Background(), &gateonv1.UpdateServiceRequest{Service: evil})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("operator repointing a credential-backed service over gRPC: got %v, want PermissionDenied", err)
		}
	})
}

// TestAdminMayBindCredentialMiddleware: everything the operator is refused, an
// administrator may do -- bind a credential middleware to a route, over REST and
// gRPC.
func TestAdminMayBindCredentialMiddleware(t *testing.T) {
	t.Run("REST", func(t *testing.T) {
		a := newRouteAPI(t, auth.RoleAdmin)
		rt := credentialRoute("admin-bind", "svc-evil", "cred-hdr")
		if code := a.putRouteREST(t, rt); code != http.StatusOK {
			t.Fatalf("PUT /v1/routes as admin binding a credential middleware: got %d, want 200", code)
		}
		if !a.hasRoute(rt.Id) {
			t.Fatal("admin's route was not stored")
		}
	})
	t.Run("gRPC", func(t *testing.T) {
		a := newRouteAPI(t, auth.RoleAdmin)
		rt := credentialRoute("admin-grpc", "svc-evil", "cred-qry")
		if _, err := a.grpc.UpdateRoute(context.Background(), &gateonv1.UpdateRouteRequest{Route: rt}); err != nil {
			t.Fatalf("gRPC UpdateRoute as admin binding a credential middleware: %v", err)
		}
		if !a.hasRoute(rt.Id) {
			t.Fatal("admin's route was not stored")
		}
	})
}

// TestViewerCannotWriteRoutes: the base RBAC still applies -- a viewer cannot
// write a route at all, credential middleware or not, so the binding rule is a
// second gate behind write, not a replacement for it.
func TestViewerCannotWriteRoutes(t *testing.T) {
	a := newRouteAPI(t, auth.RoleViewer)
	rt := credentialRoute("viewer-route", "svc-legit", "plain")
	if code := a.putRouteREST(t, rt); code != http.StatusForbidden {
		t.Fatalf("PUT /v1/routes as viewer: got %d, want 403", code)
	}
	_, err := a.grpc.UpdateRoute(context.Background(), &gateonv1.UpdateRouteRequest{Route: rt})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("gRPC UpdateRoute as viewer: got %v, want PermissionDenied", err)
	}
	if a.hasRoute(rt.Id) {
		t.Fatal("viewer wrote a route")
	}
}
