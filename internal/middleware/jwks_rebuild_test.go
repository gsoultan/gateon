// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// jwksIdP serves an OIDC discovery document and the JWKS it points at, for one
// RSA signing key.
func jwksIdP(t *testing.T, key *rsa.PublicKey, kid string) *httptest.Server {
	t.Helper()
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestJWKSRouteRebuildsDoNotLeakRefreshers covers what a route with JWKS-backed
// authentication costs every time its chain is rebuilt.
//
// ApplyRouteMiddlewares builds a fresh middleware for every chain, and a chain
// is rebuilt on every route, service or middleware change and after every
// memory-pressure purge. For "jwt" with a jwks_url and for "oidc", that build
// ran keyfunc.NewDefault, which starts an hourly JWKS refresh goroutine bound
// to context.Background(). Chains have no teardown, so nothing ever stopped
// one: each rebuild left another refresher -- and its HTTP client and key
// storage -- running for the life of the process.
func TestJWKSRouteRebuildsDoNotLeakRefreshers(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "rebuild-key"
	idp := jwksIdP(t, &key.PublicKey, kid)

	cases := map[string]map[string]string{
		"jwt with jwks_url": {"type": "jwt", "jwks_url": idp.URL + "/jwks"},
		"oidc":              {"type": "oidc", "issuer": idp.URL},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			def := &gateonv1.Middleware{Id: "authn", Type: "auth", Config: cfg}
			dir := t.TempDir()
			build := func() Middleware {
				t.Helper()
				mw, err := NewFactory(nil, nil, nil, nil, dir).Create(def, "route-a")
				if err != nil {
					t.Fatalf("build: %v", err)
				}
				return mw
			}

			// The first build may start the one refresher this key set needs.
			build()
			before := runtime.NumGoroutine()
			const rebuilds = 60
			var last Middleware
			for range rebuilds {
				last = build()
			}
			if grown := runtime.NumGoroutine() - before; grown > rebuilds/2 {
				t.Fatalf("%d rebuilds of one route left %d more goroutines running: "+
					"every chain build starts a JWKS refresher that nothing stops", rebuilds, grown)
			}

			// And the chain built last still authenticates with that key set.
			claims := jwt.MapClaims{"sub": "user-1", "exp": time.Now().Add(time.Hour).Unix()}
			if cfg["type"] == "oidc" {
				claims["iss"] = idp.URL
			}
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			tok.Header["kid"] = kid
			signed, err := tok.SignedString(key)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "/api", nil)
			req.Header.Set("Authorization", "Bearer "+signed)
			rr := httptest.NewRecorder()
			last(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("a token signed by the configured key set got %d, want 200", rr.Code)
			}
		})
	}
}
