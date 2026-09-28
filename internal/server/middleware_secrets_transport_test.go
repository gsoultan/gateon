// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/entrypoint"
	dmw "github.com/gsoultan/gateon/internal/domain/middleware"
	"github.com/gsoultan/gateon/internal/domain/route"
	"github.com/gsoultan/gateon/internal/domain/service"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/server/handlers"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
)

// secretLadenMiddlewares is one middleware of every type that carries a
// secret, with a distinct random value in every secret field, and the values.
// Written out field by field rather than generated from the classification the
// fix uses, so a secret the classification misses shows up as a leak. Every
// one of them builds: the save path proves a config can be built before it is
// stored, so a round trip also proves the kept secrets are the real ones.
func secretLadenMiddlewares(t *testing.T) ([]*gateonv1.Middleware, []string) {
	t.Helper()
	var values []string
	r := func() string {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		v := "S3CR3T" + hex.EncodeToString(b)
		values = append(values, v)
		return v
	}
	mw := func(id, typ string, cfg map[string]string) *gateonv1.Middleware {
		return &gateonv1.Middleware{Id: id, Name: id, Type: typ, Config: cfg}
	}
	mws := []*gateonv1.Middleware{
		mw("auth-jwt", "auth", map[string]string{"type": "jwt", "secret": r(), "issuer": "https://idp.example.test"}),
		mw("auth-paseto", "auth", map[string]string{"type": "paseto", "secret": r()}),
		mw("auth-apikey", "auth", map[string]string{"type": "apikey", "header": "X-API-Key",
			"key_" + r(): "tenant-a", "key_" + r(): "tenant-b", "key_" + r(): "tenant-c"}),
		mw("auth-basic-users", "auth", map[string]string{"type": "basic", "realm": "Test",
			"users": "alice:" + r() + ",bob:" + r() + ",carol:" + r()}),
		mw("auth-basic-single", "auth", map[string]string{"type": "basic", "username": "admin", "password": r()}),
		mw("auth-oauth2", "auth", map[string]string{"type": "oauth2",
			"introspection_url": "https://idp.example.test/introspect", "client_id": "gw", "client_secret": r()}),
		mw("oidc-login", "oidc", map[string]string{"issuer": "https://idp.example.test", "client_id": "gw",
			"client_secret": r(), "redirect_url": "https://app.example.test/callback"}),
		mw("hmac", "hmac", map[string]string{"secret": r()}),
		mw("turnstile", "turnstile", map[string]string{"secret": r(), "site_key": "public-site-key"}),
		mw("bot", "bot_management", map[string]string{"secret_key": r()}),
		mw("pow", "pow", map[string]string{"secret": r()}),
		mw("deception", "deception", map[string]string{"canary_header": "X-Canary", "canary_token": r()}),
		mw("headers", "headers", map[string]string{"set_request_Authorization": "Bearer " + r(),
			"add_request_X-Api-Key": r(), "set_response_X-Session-Token": r(), "set_request_X-Env": "visible-env"}),
		mw("rewrite", "rewrite", map[string]string{"query_access_token": r(), "query_api_key": r(),
			"query_lang": "visible-lang"}),
	}
	return mws, values
}

// mwNoopInvalidator stands in for the proxy cache: these tests read what was
// stored, not what a route serves.
type mwNoopInvalidator struct{}

func (mwNoopInvalidator) InvalidateRoute(string)                      {}
func (mwNoopInvalidator) InvalidateRoutes(func(*gateonv1.Route) bool) {}
func (mwNoopInvalidator) InvalidateTLS()                              {}
func (mwNoopInvalidator) InvalidateWAF()                              {}

// mwAPI serves the middleware API the way run.go mounts it -- REST on the mux,
// Connect beside it, gRPC by content type -- to a caller of one role, over a
// real middleware store and the real factory as the save path's build check.
type mwAPI struct {
	url  string
	http *http.Client
	grpc gateonv1.ApiServiceClient
	path string
	reg  *config.MiddlewareRegistry
}

func newMwAPI(t *testing.T, role string) (*mwAPI, []string) {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "middlewares.json")
	reg := config.NewMiddlewareRegistry(path)
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	mws, values := secretLadenMiddlewares(t)
	for _, m := range mws {
		if err := reg.Update(context.Background(), m); err != nil {
			t.Fatalf("store %s: %v", m.Id, err)
		}
	}
	factory := middleware.NewFactory(nil, nil, nil, nil, dir)
	svc := &api.ApiService{Middlewares: reg, Routes: routes, MiddlewareValidator: factory}
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	eps := config.NewEntryPointRegistry(filepath.Join(dir, "entrypoints.json"))
	deps := &handlers.Deps{
		MwService:      dmw.NewService(reg, routes, mwNoopInvalidator{}, factory, nil, logger.Default()),
		RouteService:   route.NewService(routes, mwNoopInvalidator{}, logger.Default()),
		ServiceService: service.NewService(services, routes, mwNoopInvalidator{}, logger.Default()),
		EpService:      entrypoint.NewService(eps, mwNoopInvalidator{}, logger.Default()),
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
	return &mwAPI{url: srv.URL, http: srv.Client(), grpc: gateonv1.NewApiServiceClient(conn), path: path, reg: reg}, values
}

func (a *mwAPI) do(t *testing.T, method, path string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, a.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

// snapshot is what is stored: every middleware's live config, and the file.
func (a *mwAPI) snapshot(t *testing.T) (map[string]*gateonv1.Middleware, []byte) {
	t.Helper()
	live := map[string]*gateonv1.Middleware{}
	for _, m := range a.reg.List(context.Background()) {
		c, ok := proto.Clone(m).(*gateonv1.Middleware)
		if !ok {
			t.Fatal("clone")
		}
		live[m.Id] = c
	}
	file, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	return live, file
}

func (a *mwAPI) requireUnchanged(t *testing.T, what string, live map[string]*gateonv1.Middleware, file []byte) {
	t.Helper()
	gotLive, gotFile := a.snapshot(t)
	for id, want := range live {
		if !proto.Equal(gotLive[id], want) {
			t.Errorf("after %s, middleware %s differs:\n got %v\nwant %v", what, id, gotLive[id], want)
		}
	}
	if len(gotLive) != len(live) {
		t.Errorf("after %s, %d middlewares are stored, want %d", what, len(gotLive), len(live))
	}
	if !bytes.Equal(gotFile, file) {
		t.Errorf("after %s, middlewares.json differs:\n got %s\nwant %s", what, gotFile, file)
	}
}

func requireNoMwSecret(t *testing.T, who, transport string, got []byte, values []string) {
	t.Helper()
	for _, v := range values {
		if bytes.Contains(got, []byte(v)) {
			t.Errorf("%s handed %s the stored middleware secret %q", transport, who, v)
		}
	}
}

// listREST reads every middleware over REST and returns the body and the
// middlewares in it.
func (a *mwAPI) listREST(t *testing.T) ([]byte, []*gateonv1.Middleware) {
	t.Helper()
	code, body := a.do(t, http.MethodGet, "/v1/middlewares?page_size=100", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/middlewares: %d %s", code, body)
	}
	var res gateonv1.ListMiddlewaresResponse
	if err := protojson.Unmarshal(body, &res); err != nil {
		t.Fatalf("decode the list: %v", err)
	}
	return body, res.GetMiddlewares()
}

// TestMiddlewareReadGivesNoWriterAStoredSecret is the defect: with a distinct
// secret stored in every secret field of every middleware type that has one,
// an administrator's or an operator's read of the middlewares -- over REST,
// Connect and gRPC -- carries none of them, and saving back what was read,
// unchanged, leaves every stored secret exactly as it was. Both roles used to
// read every basic-auth password, signing key, client secret and API key.
func TestMiddlewareReadGivesNoWriterAStoredSecret(t *testing.T) {
	for _, role := range []string{auth.RoleAdmin, auth.RoleOperator} {
		t.Run(role+"/REST", func(t *testing.T) {
			a, values := newMwAPI(t, role)
			live, file := a.snapshot(t)
			body, mws := a.listREST(t)
			requireNoMwSecret(t, role, "GET /v1/middlewares", body, values)
			for _, m := range mws {
				wire, err := protojson.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				code, out := a.do(t, http.MethodPut, "/v1/middlewares", wire)
				if code != http.StatusOK {
					t.Fatalf("PUT /v1/middlewares %s, unchanged from the read: %d %s", m.Id, code, out)
				}
				requireNoMwSecret(t, role, "the PUT /v1/middlewares response", out, values)
			}
			a.requireUnchanged(t, "an unchanged REST read and save", live, file)
		})
		t.Run(role+"/Connect", func(t *testing.T) {
			a, values := newMwAPI(t, role)
			code, body := a.do(t, http.MethodPost, "/"+gateonv1connect.ApiServiceName+"/ListMiddlewares", []byte("{}"))
			requireNoMwSecret(t, role, "Connect ListMiddlewares", body, values)
			// The Connect handler does not serve this RPC (it answers
			// unimplemented); if it ever does, it must serve the same view.
			if code != http.StatusOK && code != http.StatusNotFound && !bytes.Contains(body, []byte("unimplemented")) {
				t.Fatalf("Connect ListMiddlewares answered %d %s", code, body)
			}
		})
		t.Run(role+"/gRPC", func(t *testing.T) {
			a, values := newMwAPI(t, role)
			live, file := a.snapshot(t)
			resp, err := a.grpc.ListMiddlewares(context.Background(), &gateonv1.ListMiddlewaresRequest{})
			if err != nil {
				t.Fatalf("gRPC ListMiddlewares: %v", err)
			}
			wire, err := proto.Marshal(resp)
			if err != nil {
				t.Fatal(err)
			}
			requireNoMwSecret(t, role, "gRPC ListMiddlewares", wire, values)
			if len(resp.GetMiddlewares()) != len(live) {
				t.Fatalf("gRPC ListMiddlewares returned %d middlewares, want %d", len(resp.GetMiddlewares()), len(live))
			}
			for _, m := range resp.GetMiddlewares() {
				if _, err := a.grpc.UpdateMiddleware(context.Background(),
					&gateonv1.UpdateMiddlewareRequest{Middleware: m}); err != nil {
					t.Fatalf("gRPC UpdateMiddleware %s, unchanged from the read: %v", m.Id, err)
				}
			}
			a.requireUnchanged(t, "an unchanged gRPC read and save", live, file)
		})
	}
}

// TestMiddlewareReadMasksEveryHeaderAndQueryValueForAViewer: a viewer reads no
// secret, and no value the headers or rewrite middlewares set -- whatever the
// header or parameter is called -- while a writer still reads the values whose
// names give no credential away.
func TestMiddlewareReadMasksEveryHeaderAndQueryValueForAViewer(t *testing.T) {
	visible := []string{"visible-env", "visible-lang"}
	t.Run("viewer/REST", func(t *testing.T) {
		a, values := newMwAPI(t, auth.RoleViewer)
		body, _ := a.listREST(t)
		requireNoMwSecret(t, "a viewer", "GET /v1/middlewares", body, append(values, visible...))
	})
	t.Run("viewer/gRPC", func(t *testing.T) {
		a, values := newMwAPI(t, auth.RoleViewer)
		resp, err := a.grpc.ListMiddlewares(context.Background(), &gateonv1.ListMiddlewaresRequest{})
		if err != nil {
			t.Fatalf("gRPC ListMiddlewares: %v", err)
		}
		wire, err := proto.Marshal(resp)
		if err != nil {
			t.Fatal(err)
		}
		requireNoMwSecret(t, "a viewer", "gRPC ListMiddlewares", wire, append(values, visible...))
	})
	t.Run("operator still reads plain values", func(t *testing.T) {
		a, _ := newMwAPI(t, auth.RoleOperator)
		body, _ := a.listREST(t)
		for _, v := range visible {
			if !bytes.Contains(body, []byte(v)) {
				t.Errorf("an operator could not read %q, a value whose header or parameter name is no "+
					"credential; masking covers credentials for writers, not every value", v)
			}
		}
	})
}

// TestConfigExportCarriesNoMiddlewareSecretAndImportKeepsThem: the export an
// administrator downloads carries no stored secret, and importing it back into
// the same gateway keeps every one of them exactly. Export used to write every
// middleware secret in the clear into a file meant to be passed around.
func TestConfigExportCarriesNoMiddlewareSecretAndImportKeepsThem(t *testing.T) {
	a, values := newMwAPI(t, auth.RoleAdmin)
	live, file := a.snapshot(t)
	code, exported := a.do(t, http.MethodGet, "/v1/config/export", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/config/export: %d %s", code, exported)
	}
	requireNoMwSecret(t, "an administrator", "GET /v1/config/export", exported, values)

	code, out := a.do(t, http.MethodPost, "/v1/config/import?dry_run=true", exported)
	if code != http.StatusOK {
		t.Fatalf("import preview: %d %s", code, out)
	}
	requireNoMwSecret(t, "an administrator", "the import preview", out, values)

	code, out = a.do(t, http.MethodPost, "/v1/config/import", exported)
	if code != http.StatusOK || !bytes.Contains(out, []byte(`"success":true`)) || bytes.Contains(out, []byte("errors")) {
		t.Fatalf("importing the export back: %d %s", code, out)
	}
	a.requireUnchanged(t, "an export imported back", live, file)
}
