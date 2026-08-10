// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// managementRequest builds a request as it arrives on the management
// entrypoint, which is the path that used to bypass authentication.
func managementRequest(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	ctx := context.WithValue(r.Context(), middleware.EntryPointIDContextKey, "management")
	return r.WithContext(ctx)
}

func setupTestDeps(authSvc auth.Service) BaseHandlerDeps {
	return BaseHandlerDeps{
		ProxyHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Stand-in for the real management API. If the handler ever reaches
			// this, the request was served.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"served":true}`))
		}),
		RouteStore: &mockRouteStore{},
		GlobalReg: &mockGlobalReg{config: &gateonv1.GlobalConfig{
			Auth:       &gateonv1.AuthConfig{Enabled: true},
			Management: &gateonv1.ManagementConfig{},
		}},
		Auth: authSvc,
	}
}

// TestManagementAPI_ClosedBeforeSetup is the regression test for the first-run
// authentication bypass.
//
// Root cause: on a first run internal/inits returns a nil *auth.Manager because
// global.json does not exist yet. CreateBaseHandler captured that nil by value
// and, on finding no auth service, served the management API anyway. A fresh
// gateway on a routable address therefore exposed routes, services, TLS
// material and config import to any unauthenticated caller.
//
// Against the unfixed handler every management path below returns 200.
//
// Both shapes of "no auth service" are exercised. The literal nil is what
// WithAuthManager(nil) produced before this fix and is the shape that actually
// reached the vulnerable branch; the empty Holder is what a first run produces
// now. Both must deny — a defence that only holds for the representation we
// happen to construct today is not a defence.
func TestManagementAPI_ClosedBeforeSetup(t *testing.T) {
	protected := []string{
		"/v1/routes",
		"/v1/services",
		"/v1/global",
		"/v1/certificates",
		"/v1/users",
		"/v1/config/export",
		"/metrics",
		"/gateon.v1.ApiService/GetGlobalConfig",
	}

	shapes := map[string]auth.Service{
		"literal nil (pre-fix shape)": nil,
		"empty holder (first run)":    auth.NewHolder(nil),
	}

	for shape, svc := range shapes {
		t.Run(shape, func(t *testing.T) {
			deps := setupTestDeps(svc)
			handler := CreateBaseHandler(http.NotFoundHandler(), deps, nil, http.NewServeMux())

			for _, path := range protected {
				t.Run(path, func(t *testing.T) {
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, managementRequest(http.MethodGet, path))

					if rec.Code == http.StatusOK {
						t.Fatalf("%s served with no auth service installed (status 200) — "+
							"the management API must not be reachable before setup", path)
					}
					if rec.Code != http.StatusServiceUnavailable {
						t.Errorf("%s: want 503 while auth is unavailable, got %d", path, rec.Code)
					}
				})
			}
		})
	}
}

// TestSetupAndHealthStayOpenBeforeSetup guards the other direction: failing
// closed must not brick the very endpoints an operator needs to complete setup.
func TestSetupAndHealthStayOpenBeforeSetup(t *testing.T) {
	deps := setupTestDeps(auth.NewHolder(nil))
	handler := CreateBaseHandler(http.NotFoundHandler(), deps, nil, http.NewServeMux())

	open := []string{"/v1/setup", "/v1/setup/required", "/healthz", "/readyz"}

	for _, path := range open {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, managementRequest(http.MethodGet, path))

			if rec.Code == http.StatusServiceUnavailable {
				t.Errorf("%s must stay reachable before setup, got 503", path)
			}
		})
	}
}

// TestAuthHolderSwapTakesEffectWithoutRestart covers the second half of the
// same bug. Setup builds an auth.Manager mid-process and used to publish it
// only to ApiService, so the HTTP handler kept the startup nil and went on
// serving unauthenticated for the life of the process — an operator who
// completed setup was still exposed until they restarted the gateway.
func TestAuthHolderSwapTakesEffectWithoutRestart(t *testing.T) {
	holder := auth.NewHolder(nil)
	deps := setupTestDeps(holder)
	handler := CreateBaseHandler(http.NotFoundHandler(), deps, nil, http.NewServeMux())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, managementRequest(http.MethodGet, "/v1/routes"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("before setup: want 503, got %d", rec.Code)
	}

	// Setup completes and swaps a real manager in.
	mgr, err := auth.NewManager("sqlite::memory:", "test-secret-key-32-bytes-minimum!", logger.Default())
	if err != nil {
		t.Fatalf("auth.NewManager: %v", err)
	}
	defer mgr.Close()
	holder.Set(mgr)

	// The same handler instance must now demand a token instead of either
	// serving the request or continuing to report "unavailable".
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, managementRequest(http.MethodGet, "/v1/routes"))

	if rec.Code == http.StatusOK {
		t.Fatal("after setup the handler served /v1/routes unauthenticated")
	}
	if rec.Code == http.StatusServiceUnavailable {
		t.Fatal("after setup the handler still reports auth unavailable — the swap did not take effect")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("after setup: want 401 for a request with no token, got %d", rec.Code)
	}
}
