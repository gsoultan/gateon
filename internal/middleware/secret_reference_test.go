// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestJWTRouteRefusesASecretItCannotResolve builds a JWT route whose secret is
// a reference to a variable nobody set -- the state a route referencing Vault
// is in while Vault is down.
//
// The reference used to become the secret: the middleware built, and accepted
// a token HMAC-signed with the text "$env:..." itself. It must refuse to build
// instead; the router then serves a refusal for the route and retries it.
func TestJWTRouteRefusesASecretItCannotResolve(t *testing.T) {
	const ref = "$env:GATEON_TEST_UNSET_JWT_SECRET_7731"
	f := NewFactory(nil, &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{}}, nil, nil, t.TempDir())
	mw, err := f.Create(&gateonv1.Middleware{
		Id: "jwt-ref", Type: "auth", Config: map[string]string{"type": "jwt", "secret": ref},
	}, "jwt-route")
	if err != nil {
		return
	}
	tok, signErr := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "attacker", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(ref))
	if signErr != nil {
		t.Fatal(signErr)
	}
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(rec, req)
	t.Fatalf("built a JWT middleware from an unresolvable secret reference; a token signed with the reference text got %d", rec.Code)
}
