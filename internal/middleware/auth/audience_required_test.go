// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
)

// A provider's published keys sign the tokens of every application it serves.
// With "Audience (optional)" left blank, OIDC and JWKS-verified JWT accepted a
// token the provider issued to any other application -- for a public
// provider, any application at all (2026-10-02 truth T5). Both now refuse to
// build without an audience, and OIDC refuses before it asks the provider
// anything (ADR 0043).
func TestAKeySetValidatorWithNoAudienceIsRefused(t *testing.T) {
	idp := testutil.NewFakeOIDCProvider(t, "some-other-app")
	t.Run("oidc", func(t *testing.T) {
		_, err := NewOIDCValidator(JWTConfig{Issuer: idp.Issuer(), Audience: "  "})
		if !errors.Is(err, ErrAudienceRequired) {
			t.Fatalf("got %v, want ErrAudienceRequired", err)
		}
		if n := idp.DiscoveryCalls.Load(); n != 0 {
			t.Errorf("a refused config asked the provider for discovery %d times", n)
		}
	})
	t.Run("jwt with a jwks url", func(t *testing.T) {
		_, err := NewJWTValidator(JWTConfig{JWKSURL: idp.Server.URL + "/jwks"})
		if !errors.Is(err, ErrAudienceRequired) {
			t.Fatalf("got %v, want ErrAudienceRequired", err)
		}
	})
	t.Run("jwt with a shared secret needs none", func(t *testing.T) {
		if _, err := NewJWTValidator(JWTConfig{Secret: []byte(testSecret)}); err != nil {
			t.Fatalf("a shared-secret validator with no audience was refused: %v", err)
		}
	})
}

// With an audience set, a token the same provider issued to another
// application is refused and one issued to this API passes. The named opt-out
// is the one way to accept any audience, and it does exactly that.
func TestATokenIssuedForAnotherAudienceIsRefused(t *testing.T) {
	other := testutil.NewFakeOIDCProvider(t, "some-other-app")
	tok, err := other.Mint("alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cfg  JWTConfig
		want int
	}{
		{"audience set", JWTConfig{Issuer: other.Issuer(), Audience: "my-api"}, http.StatusUnauthorized},
		{"audience matches", JWTConfig{Issuer: other.Issuer(), Audience: "some-other-app"}, http.StatusOK},
		{"named opt-out", JWTConfig{Issuer: other.Issuer(), AllowAnyAudience: true}, http.StatusOK},
	} {
		v, err := NewOIDCValidator(tc.cfg)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		req := httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		v.Handler(okHandler()).ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: a token issued to some-other-app got %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}
