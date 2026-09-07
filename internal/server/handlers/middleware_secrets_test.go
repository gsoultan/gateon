// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	domainmw "github.com/gsoultan/gateon/internal/domain/middleware"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// A middleware's config is a map[string]string, and for the auth middlewares the
// values in it are credentials: "secret" for jwt, hmac and pow, "password" for
// basic auth, "client_secret" for oidc.
//
// The list endpoint returns the stored Middleware messages as they are, and
// RoleViewer -- the lowest role there is, read-only by definition -- holds
// ActionRead on ResourceMiddlewares. So the question is whether a viewer can
// read the signing key for the routes the gateway is protecting.

// secretsStore serves one middleware carrying every credential shape.
type secretsStore struct {
	domainmw.Service
	mw *gateonv1.Middleware
}

func (s *secretsStore) ListPaginated(context.Context, int32, int32, string) ([]*gateonv1.Middleware, int32) {
	return []*gateonv1.Middleware{s.mw}, 1
}

// TestMiddlewareListDoesNotHandCredentialsToAViewer is the question stated as a
// test.
//
// If it fails, a read-only account can read the HMAC signing key for a protected
// route and mint tokens the gateway will accept for it -- the credential is for
// the proxied application, not the dashboard, so this crosses from "can see the
// config" to "can reach the backend as anyone".
func TestMiddlewareListDoesNotHandCredentialsToAViewer(t *testing.T) {
	const signingKey = "SUPER-SECRET-SIGNING-KEY"

	d := &Deps{MwService: &secretsStore{mw: &gateonv1.Middleware{
		Id:   "jwt-1",
		Name: "api-auth",
		Type: "jwt",
		Config: map[string]string{
			"secret":        signingKey,
			"password":      "hunter2",
			"client_secret": "oidc-client-secret",
			"issuer":        "https://idp.example.com", // not a credential
		},
	}}}

	mux := http.NewServeMux()
	registerMiddlewareHandlers(mux, nil, d)

	req := httptest.NewRequest(http.MethodGet, "/v1/middlewares", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "v-1", Username: "viewer", Role: auth.RoleViewer}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("a viewer got %d listing middlewares; the role is supposed to have "+
			"read access, so this test is not exercising what it thinks", rr.Code)
	}

	body := rr.Body.String()
	for _, leaked := range []struct{ key, value string }{
		{"secret", signingKey},
		{"password", "hunter2"},
		{"client_secret", "oidc-client-secret"},
	} {
		if strings.Contains(body, leaked.value) {
			t.Errorf("a viewer read the %q value %q from GET /v1/middlewares.\n"+
				"RoleViewer is the lowest role there is and holds ActionRead on "+
				"ResourceMiddlewares, and the handler returns the stored config map "+
				"unchanged. For jwt and hmac that value is the signing key for a "+
				"protected route: whoever has it can mint a token the gateway "+
				"accepts, so a read-only dashboard account becomes access to the "+
				"backend as any user. Credentials should be withheld or masked on "+
				"read; a caller who needs to change one can write it without being "+
				"shown the current value.",
				leaked.key, leaked.value)
		}
	}

	// Non-secret configuration must still be visible, or the screen is useless.
	if !strings.Contains(body, "https://idp.example.com") {
		t.Error("the issuer was withheld too; masking should cover credentials, not " +
			"the whole config, or the middleware list stops being usable")
	}
}

// TestMiddlewareListStillShowsSecretsToSomeoneWhoCanChangeThem draws the line.
//
// Write permission is the boundary. Someone who can set the secret gains nothing
// by reading it -- they can already replace it with one they chose -- and
// masking it for them would break config export, which operators use for backup
// and which has to round-trip.
func TestMiddlewareListStillShowsSecretsToSomeoneWhoCanChangeThem(t *testing.T) {
	const signingKey = "SUPER-SECRET-SIGNING-KEY"
	d := &Deps{MwService: &secretsStore{mw: &gateonv1.Middleware{
		Id: "jwt-1", Type: "jwt",
		Config: map[string]string{"secret": signingKey},
	}}}

	mux := http.NewServeMux()
	registerMiddlewareHandlers(mux, nil, d)

	for _, role := range []string{auth.RoleAdmin, auth.RoleOperator} {
		req := httptest.NewRequest(http.MethodGet, "/v1/middlewares", nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
			&auth.Claims{ID: "u", Username: "u", Role: role}))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if !strings.Contains(rr.Body.String(), signingKey) {
			t.Errorf("%s could not read a secret they are allowed to overwrite; "+
				"config export round-trips through this and would restore a "+
				"placeholder as the credential", role)
		}
	}
}

// TestMiddlewareMaskingDoesNotMutateTheStoredConfig is the incident case.
//
// The messages come from the live configuration registry. Masking them in place
// would not hide the credential, it would delete it from the running gateway on
// a GET -- and the next request through that route would fail to authenticate.
func TestMiddlewareMaskingDoesNotMutateTheStoredConfig(t *testing.T) {
	const signingKey = "SUPER-SECRET-SIGNING-KEY"
	stored := &gateonv1.Middleware{
		Id: "jwt-1", Type: "jwt",
		Config: map[string]string{"secret": signingKey},
	}
	d := &Deps{MwService: &secretsStore{mw: stored}}

	mux := http.NewServeMux()
	registerMiddlewareHandlers(mux, nil, d)

	req := httptest.NewRequest(http.MethodGet, "/v1/middlewares", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "v", Username: "viewer", Role: auth.RoleViewer}))
	mux.ServeHTTP(httptest.NewRecorder(), req)

	if stored.Config["secret"] != signingKey {
		t.Fatalf("the stored secret is now %q. A viewer's read request rewrote the "+
			"live configuration, so every request through this route now fails to "+
			"authenticate.", stored.Config["secret"])
	}
}
