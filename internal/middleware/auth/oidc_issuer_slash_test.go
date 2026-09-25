// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
)

// TestOIDCValidatorAcceptsATrailingSlashIssuer validates a token from a
// provider whose issuer ends in "/", as Auth0's does. The validator trimmed the
// slash from the issuer discovery reported and then compared the token's iss
// exactly, so every token such a provider issued was refused as "invalid
// issuer".
func TestOIDCValidatorAcceptsATrailingSlashIssuer(t *testing.T) {
	idp := testutil.NewFakeOIDCProviderAt(t, "api", "/")
	v, err := NewOIDCValidator(idp.Issuer(), "api", AuthBaseConfig{})
	if err != nil {
		t.Fatalf("NewOIDCValidator: %v", err)
	}
	tok, err := idp.Mint("user-1")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	v.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a token from issuer %q got %d: %s", idp.Issuer(), rec.Code, rec.Body)
	}
}
