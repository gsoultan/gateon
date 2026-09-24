// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// FakeOIDCProvider is the smallest OpenID provider go-oidc accepts: a
// discovery document, a JWKS, and a token endpoint that mints an RS256 ID
// token for whatever code it is handed.
type FakeOIDCProvider struct {
	Server   *httptest.Server
	ClientID string
	key      *rsa.PrivateKey
	// DiscoveryDown makes the discovery endpoint answer 503, standing in for a
	// provider that is unreachable at the moment the gateway needs it.
	DiscoveryDown atomic.Bool
	// DiscoveryCalls counts requests to the discovery endpoint.
	DiscoveryCalls atomic.Int64
}

// NewFakeOIDCProvider starts a provider that issues tokens for clientID and
// stops it when the test ends.
func NewFakeOIDCProvider(t testing.TB, clientID string) *FakeOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := &FakeOIDCProvider{key: key, ClientID: clientID}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/token", p.token)
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Server.Close)
	return p
}

// Issuer is the provider's issuer URL.
func (p *FakeOIDCProvider) Issuer() string { return p.Server.URL }

func (p *FakeOIDCProvider) discovery(w http.ResponseWriter, _ *http.Request) {
	p.DiscoveryCalls.Add(1)
	if p.DiscoveryDown.Load() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	u := p.Server.URL
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                u,
		"authorization_endpoint":                u + "/authorize",
		"token_endpoint":                        u + "/token",
		"jwks_uri":                              u + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *FakeOIDCProvider) jwks(w http.ResponseWriter, _ *http.Request) {
	enc := base64.RawURLEncoding
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
		"n": enc.EncodeToString(p.key.N.Bytes()),
		"e": enc.EncodeToString(big.NewInt(int64(p.key.E)).Bytes()),
	}}})
}

func (p *FakeOIDCProvider) token(w http.ResponseWriter, _ *http.Request) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   p.Server.URL,
		"sub":   "user-1",
		"aud":   p.ClientID,
		"email": "user-1@example.com",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(p.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": signed,
	})
}

// HungServer accepts connections and never answers until the test ends — the
// shape of a provider behind a black-holing load balancer, which a client
// with no timeout waits on forever.
func HungServer(t testing.TB) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Cleanups run last-registered first: release the handlers, then Close,
	// which waits for them.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return srv
}
