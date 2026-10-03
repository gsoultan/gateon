// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gsoultan/gateon/internal/testutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	redigo "github.com/redis/go-redis/v9"
)

// The dashboard offers "Enable Revocation" for JWT, PASETO and OIDC (ADR
// 0046). Only the JWT branch read it, and only with Redis configured: PASETO
// and OIDC kept accepting a token the operator had revoked, and JWT without
// Redis -- the default -- built with the switch on and checked nothing.

const (
	revocationJWTSecret    = "revocation-test-secret-0123456789"
	revocationPasetoSecret = "0123456789abcdef0123456789abcdef"
)

// revocationRedis is the smallest redis.Client the revocation store can read:
// EXISTS over a set of keys. The embedded nil Cmdable covers the rest of the
// interface; reaching for it would fail the test, not pass it.
type revocationRedis struct {
	redigo.Cmdable
	mu   sync.Mutex
	keys map[string]bool
}

func newRevocationRedis(revoked ...string) *revocationRedis {
	r := &revocationRedis{keys: map[string]bool{}}
	for _, jti := range revoked {
		r.keys["revoked_jti:"+jti] = true
	}
	return r
}

func (r *revocationRedis) Exists(_ context.Context, keys ...string) *redigo.IntCmd {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, k := range keys {
		if r.keys[k] {
			n++
		}
	}
	return redigo.NewIntResult(n, nil)
}

func (r *revocationRedis) Subscribe(context.Context, ...string) *redigo.PubSub { return nil }
func (r *revocationRedis) Close() error                                        { return nil }

func buildAuthWith(t *testing.T, f *Factory, cfg map[string]string) (Middleware, error) {
	t.Helper()
	return f.Create(&gateonv1.Middleware{Id: "auth-under-test", Type: "auth", Config: cfg}, "route-under-test")
}

func bearer(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func mintHS256(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(revocationJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mintPaseto(t *testing.T, jti string) string {
	t.Helper()
	key, err := paseto.V4SymmetricKeyFromBytes([]byte(revocationPasetoSecret))
	if err != nil {
		t.Fatal(err)
	}
	tok := paseto.NewToken()
	tok.SetString("sub", "alice")
	tok.SetString("jti", jti)
	tok.SetExpiration(time.Now().Add(time.Hour))
	return tok.V4Encrypt(key, nil)
}

// revocationCase is one auth type that offers the switch: its config, and a
// token it would otherwise accept, carrying the given jti.
type revocationCase struct {
	name string
	cfg  func() map[string]string
	mint func(t *testing.T, jti string) string
}

func revocationCases(t *testing.T) []revocationCase {
	idp := testutil.NewFakeOIDCProvider(t, "orders-api")
	return []revocationCase{
		{
			name: "jwt",
			cfg: func() map[string]string {
				return map[string]string{"type": "jwt", "secret": revocationJWTSecret, "enable_revocation": "true"}
			},
			mint: func(t *testing.T, jti string) string {
				return mintHS256(t, jwt.MapClaims{"sub": "alice", "jti": jti})
			},
		},
		{
			name: "paseto",
			cfg: func() map[string]string {
				return map[string]string{"type": "paseto", "secret": revocationPasetoSecret, "enable_revocation": "true"}
			},
			mint: mintPaseto,
		},
		{
			name: "oidc",
			cfg: func() map[string]string {
				return map[string]string{"type": "oidc", "issuer": idp.Issuer(), "audience": "orders-api", "enable_revocation": "true"}
			},
			mint: func(t *testing.T, jti string) string {
				tok, err := idp.MintWithID("alice", jti)
				if err != nil {
					t.Fatal(err)
				}
				return tok
			},
		},
	}
}

// TestRevokedTokenIsRefusedByEveryTypeThatOffersRevocation revokes one token
// ID in Redis and presents it, and an unrevoked one, to each type.
func TestRevokedTokenIsRefusedByEveryTypeThatOffersRevocation(t *testing.T) {
	for _, tc := range revocationCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFactory(newRevocationRedis("stolen-1"), nil, nil, nil, t.TempDir())
			mw, err := buildAuthWith(t, f, tc.cfg())
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if code, _ := serveAuth(mw, bearer(tc.mint(t, "stolen-1"))); code != http.StatusUnauthorized {
				t.Errorf("%s: a token whose jti is revoked in Redis got %d, want 401: "+
					"Enable Revocation was on and checked nothing", tc.name, code)
			}
			if code, _ := serveAuth(mw, bearer(tc.mint(t, "fresh-2"))); code != http.StatusOK {
				t.Errorf("%s: an unrevoked token got %d, want 200", tc.name, code)
			}
		})
	}
}

// TestRevocationWithoutRedisIsRefused builds each type with the switch on and
// no Redis configured. There is nowhere a revoked token ID could be recorded,
// so the switch would check an empty list; the build says so instead.
func TestRevocationWithoutRedisIsRefused(t *testing.T) {
	for _, tc := range revocationCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildAuthWith(t, NewFactory(nil, nil, nil, nil, t.TempDir()), tc.cfg())
			if err == nil {
				t.Fatalf("%s with enable_revocation=true and no Redis built; the switch would check nothing", tc.name)
			}
			if !strings.Contains(err.Error(), "Redis") {
				t.Errorf("%s: refusal %q does not say revocation needs Redis", tc.name, err)
			}
		})
	}
}

// TestRevocationOffStillBuildsWithoutRedis keeps the refusal to the switch: the
// same configs with it off build and serve without Redis.
func TestRevocationOffStillBuildsWithoutRedis(t *testing.T) {
	for _, tc := range revocationCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg()
			cfg["enable_revocation"] = "false"
			mw, err := buildAuthWith(t, NewFactory(nil, nil, nil, nil, t.TempDir()), cfg)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if code, _ := serveAuth(mw, bearer(tc.mint(t, "any"))); code != http.StatusOK {
				t.Errorf("%s with revocation off got %d, want 200", tc.name, code)
			}
		})
	}
}

// TestRequiredScopesAndRolesAcceptThePlaceholderFormat types the lists the way
// the dashboard's placeholders show them ("read, write"; "admin, editor"). The
// factory split on "," without trimming, so " write" and " editor" matched no
// token and every valid token was refused.
func TestRequiredScopesAndRolesAcceptThePlaceholderFormat(t *testing.T) {
	token := mintHS256(t, jwt.MapClaims{"sub": "alice", "scope": "read write", "roles": []string{"admin", "editor"}})
	for _, tc := range []struct{ name, scopes, roles string }{
		{"placeholder", "read, write", "admin, editor"},
		{"space separated scopes", "read write", "admin"},
		{"mixed and padded", " read ,write ", " editor ,admin"},
		{"trailing separators", "read,", "admin,"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mw, err := buildAuthWith(t, NewFactory(nil, nil, nil, nil, t.TempDir()), map[string]string{
				"type": "jwt", "secret": revocationJWTSecret,
				"required_scopes": tc.scopes, "required_roles": tc.roles,
			})
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if code, _ := serveAuth(mw, bearer(token)); code != http.StatusOK {
				t.Errorf("scopes %q roles %q: a token with scope \"read write\" and roles [admin editor] got %d, want 200",
					tc.scopes, tc.roles, code)
			}
		})
	}
}

// TestRequiredScopesStillRefuseAMissingOne keeps the parser from passing by
// dropping requirements: a scope the token lacks still refuses it.
func TestRequiredScopesStillRefuseAMissingOne(t *testing.T) {
	token := mintHS256(t, jwt.MapClaims{"sub": "alice", "scope": "read", "roles": []string{"admin"}})
	for _, cfg := range []map[string]string{
		{"required_scopes": "read, write"},
		{"required_scopes": "read write"},
		{"required_roles": "admin, editor"},
	} {
		cfg["type"], cfg["secret"] = "jwt", revocationJWTSecret
		mw, err := buildAuthWith(t, NewFactory(nil, nil, nil, nil, t.TempDir()), cfg)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if code, _ := serveAuth(mw, bearer(token)); code != http.StatusUnauthorized {
			t.Errorf("%v: a token lacking a required entry got %d, want 401", cfg, code)
		}
	}
}
