// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/middleware/transform"
	"github.com/gsoultan/gateon/internal/server/handlers"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestAMiddlewareSavedBackMaskedStillAuthenticates: an operator reads a
// basic-auth middleware (passwords as placeholders), saves it back with only
// its name changed, and the route in front of the backend goes on accepting
// the same users -- and not the placeholder as a password.
func TestAMiddlewareSavedBackMaskedStillAuthenticates(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	dir := t.TempDir()
	s, err := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(dir, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(dir, "services.json"))),
		WithEntryPointRegistry(config.NewEntryPointRegistry(filepath.Join(dir, "entrypoints.json"))),
		WithMiddlewareRegistry(config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))),
		WithTLSOptionRegistry(config.NewTLSOptionRegistry(filepath.Join(dir, "tls_options.json"))),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(dir, "global.json"))),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx := context.Background()
	_ = s.ServiceStore.Update(ctx, &gateonv1.Service{Id: "svc", WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}}})
	_ = s.MwStore.Update(ctx, &gateonv1.Middleware{Id: "basic-1", Name: "basic", Type: "auth",
		Config: map[string]string{"type": "basic", "realm": "t", "users": "alice:pw-alice-S3CR3T,bob:pw-bob-S3CR3T"}})
	_ = s.RouteStore.Update(ctx, &gateonv1.Route{Id: "r1", ServiceId: "svc", Rule: "PathPrefix(`/api`)", Type: "http",
		Middlewares: []string{"basic-1"}})

	apiSvc := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteStore, Services: s.ServiceStore, Globals: s.GlobalStore, EntryPoints: s.EpStore,
		Middlewares: s.MwStore, TLSOptions: s.TLSOptStore, TLSManager: s.TLSManager,
	})
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, apiSvc, handlerDeps(s))
	wrapped := transform.NewDefaultGRPCWebDetector(grpc.NewServer())
	gateway := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, wrapped, wrapped, mux)
	})
	// Over a real listener and one keep-alive client, as the dashboard's
	// browser and the e2e suite reach it.
	proxy := httptest.NewServer(gateway)
	defer proxy.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	probe := func(user, password string) int {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxy.URL+"/api/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		if user != "" {
			req.SetBasicAuth(user, password)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("probe as %q: %v", user, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := probe("alice", "pw-alice-S3CR3T"); code != http.StatusOK {
		t.Fatalf("alice before the save: %d", code)
	}
	if code := probe("", ""); code != http.StatusUnauthorized {
		t.Fatalf("no credentials before the save: %d", code)
	}

	operator := &auth.Claims{ID: "op-1", Username: "op", Role: auth.RoleOperator}
	api := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, operator))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	list := api(http.MethodGet, "/v1/middlewares", "")
	var res gateonv1.ListMiddlewaresResponse
	if err := protojson.Unmarshal(list.Body.Bytes(), &res); err != nil || len(res.Middlewares) != 1 {
		t.Fatalf("list: %v %s", err, list.Body.String())
	}
	m := res.Middlewares[0]
	m.Name = "basic, renamed"
	wire, err := protojson.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if put := api(http.MethodPut, "/v1/middlewares", string(wire)); put.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", put.Code, put.Body.String())
	}

	for _, c := range []struct {
		user, password string
		want           int
	}{
		{"alice", "pw-alice-S3CR3T", http.StatusOK},
		{"bob", "pw-bob-S3CR3T", http.StatusOK},
		{"alice", "__gateon_redacted__", http.StatusUnauthorized},
	} {
		if code := probe(c.user, c.password); code != c.want {
			t.Errorf("%s with %q after the save: %d, want %d", c.user, c.password, code, c.want)
		}
	}
}
