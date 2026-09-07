// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTValidator is the gateway's main token path, and two of its checks shipped
// with no test touching them at all: checkAudience was at 0% coverage, meaning
// nothing in the suite ever configured an audience, and formatJWTError likewise.
//
// An audience check is what stops a token minted for one service being spent at
// another. A token from a sibling service is correctly signed, unexpired, and
// from the right issuer -- audience is the only thing standing between it and a
// route it was never issued for. Untested, it either works or it does not, and
// nothing about a passing suite tells you which.

const testSecret = "test-signing-secret-not-a-real-one"

// mint signs claims with the test secret.
func mint(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// baseClaims is a token that passes everything unless a test spoils it.
func baseClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
}

// serveJWT runs one request through a validator built from cfg.
func serveJWT(t *testing.T, cfg JWTConfig, token string) *httptest.ResponseRecorder {
	t.Helper()
	cfg.Secret = []byte(testSecret)
	v, err := NewJWTValidator(cfg)
	if err != nil {
		t.Fatalf("build validator: %v", err)
	}

	h := v.Handler(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestJWTAcceptsAValidToken is the control every other test here depends on.
//
// Without it, a validator that refused everything would satisfy all the negative
// assertions below and look thoroughly tested.
func TestJWTAcceptsAValidToken(t *testing.T) {
	rr := serveJWT(t, JWTConfig{}, mint(t, baseClaims()))
	if rr.Code != http.StatusOK {
		t.Fatalf("a well-formed token got %d, want 200; every negative test in this "+
			"file would pass against a validator that denies everything", rr.Code)
	}
}

// TestJWTEnforcesAudience is the gap.
//
// This is audience confusion: an attacker who holds a legitimate token for a
// low-value service replays it at a high-value one. The token is genuine, signed
// by the right key, unexpired and from the right issuer -- the audience claim is
// the only thing that says it was not meant for this door.
func TestJWTEnforcesAudience(t *testing.T) {
	cfg := JWTConfig{Audience: "api.gateon.internal"}

	t.Run("matching audience passes", func(t *testing.T) {
		c := baseClaims()
		c["aud"] = "api.gateon.internal"
		if got := serveJWT(t, cfg, mint(t, c)).Code; got != http.StatusOK {
			t.Errorf("got %d, want 200", got)
		}
	})

	t.Run("audience list containing ours passes", func(t *testing.T) {
		// Multi-audience tokens are ordinary; an issuer mints one token good for
		// several services.
		c := baseClaims()
		c["aud"] = []string{"other.service", "api.gateon.internal", "third"}
		if got := serveJWT(t, cfg, mint(t, c)).Code; got != http.StatusOK {
			t.Errorf("got %d, want 200 — a token listing several audiences is valid "+
				"at each of them", got)
		}
	})

	t.Run("a token for another service is refused", func(t *testing.T) {
		c := baseClaims()
		c["aud"] = "reports.internal"
		if got := serveJWT(t, cfg, mint(t, c)).Code; got != http.StatusUnauthorized {
			t.Errorf("a token minted for reports.internal got %d at api.gateon.internal, "+
				"want 401. This is audience confusion: the token is genuine and "+
				"correctly signed, and the audience claim is the only thing that "+
				"says it was not meant for this service.", got)
		}
	})

	t.Run("a token with no audience is refused", func(t *testing.T) {
		if got := serveJWT(t, cfg, mint(t, baseClaims())).Code; got != http.StatusUnauthorized {
			t.Errorf("a token with no aud claim got %d, want 401 — an operator who "+
				"configured an audience asked for it to be present, and absent must "+
				"not read as satisfied", got)
		}
	})

	t.Run("no configured audience accepts anything", func(t *testing.T) {
		c := baseClaims()
		c["aud"] = "anyone.at.all"
		if got := serveJWT(t, JWTConfig{}, mint(t, c)).Code; got != http.StatusOK {
			t.Errorf("got %d, want 200 — audience is opt-in", got)
		}
	})
}

// TestJWTEnforcesIssuer covers the sibling check.
func TestJWTEnforcesIssuer(t *testing.T) {
	cfg := JWTConfig{Issuer: "https://idp.example.com"}

	c := baseClaims()
	c["iss"] = "https://idp.example.com"
	if got := serveJWT(t, cfg, mint(t, c)).Code; got != http.StatusOK {
		t.Errorf("the configured issuer got %d, want 200", got)
	}

	c = baseClaims()
	c["iss"] = "https://evil.example.com"
	if got := serveJWT(t, cfg, mint(t, c)).Code; got != http.StatusUnauthorized {
		t.Errorf("a token from another issuer got %d, want 401", got)
	}

	if got := serveJWT(t, cfg, mint(t, baseClaims())).Code; got != http.StatusUnauthorized {
		t.Errorf("a token with no iss got %d, want 401", got)
	}
}

// TestJWTRejectsExpiredTokens covers expiry and the error wording.
func TestJWTRejectsExpiredTokens(t *testing.T) {
	c := baseClaims()
	c["exp"] = time.Now().Add(-time.Hour).Unix()

	rr := serveJWT(t, JWTConfig{}, mint(t, c))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("an expired token got %d, want 401", rr.Code)
	}
	// formatJWTError exists to say "token expired" rather than leaking the
	// library's wording; a client that cannot tell expiry from a bad signature
	// cannot know whether refreshing would help.
	if body := rr.Body.String(); !strings.Contains(body, "expired") {
		t.Errorf("the response was %q, want it to name expiry — a client cannot tell "+
			"whether to refresh otherwise", body)
	}
}

// TestJWTRejectsAlgorithmConfusion pins the allowlist.
//
// alg=none and HS/RS confusion are the two oldest JWT attacks there are. The
// validator carries an explicit allowlist as defence in depth rather than
// trusting library internals, and defence in depth that nobody tests is just a
// comment.
func TestJWTRejectsAlgorithmConfusion(t *testing.T) {
	t.Run("alg=none", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims())
		s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if got := serveJWT(t, JWTConfig{}, s).Code; got != http.StatusUnauthorized {
			t.Errorf("an unsigned token got %d, want 401", got)
		}
	})

	t.Run("garbage is not a token", func(t *testing.T) {
		for _, s := range []string{"not.a.token", "", "a.b", "....."} {
			if got := serveJWT(t, JWTConfig{}, s).Code; got != http.StatusUnauthorized {
				t.Errorf("token %q got %d, want 401", s, got)
			}
		}
	})

	t.Run("wrong signing key", func(t *testing.T) {
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims()).
			SignedString([]byte("a-different-secret"))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if got := serveJWT(t, JWTConfig{}, s).Code; got != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", got)
		}
	})
}

// failingRevocationStore reports that it cannot answer.
type failingRevocationStore struct{}

func (failingRevocationStore) IsRevoked(context.Context, string) (bool, error) {
	return false, errors.New("dial tcp 10.0.0.5:6379: connect: connection refused")
}
func (failingRevocationStore) Revoke(context.Context, string, time.Duration) error { return nil }

// revokedStore reports everything as revoked.
type revokedStore struct{}

func (revokedStore) IsRevoked(context.Context, string) (bool, error)     { return true, nil }
func (revokedStore) Revoke(context.Context, string, time.Duration) error { return nil }

// TestJWTRevocationFailsClosed pins the decision the code documents at length.
//
// The store returns (false, err) when the backend is unreachable. Treating a
// failed lookup as "not revoked" honoured every revoked token for as long as
// Redis was down. Revocation is the control you reach for after a compromise,
// which makes an outage exactly the wrong moment to stop enforcing it.
func TestJWTRevocationFailsClosed(t *testing.T) {
	c := baseClaims()
	c["jti"] = "token-id-1"

	rr := serveJWT(t, JWTConfig{RevocationStore: failingRevocationStore{}}, mint(t, c))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("with the revocation store unreachable the request got %d, want 401. "+
			"A lookup that failed is not a lookup that said 'not revoked' — reading "+
			"it that way honours every revoked token for the length of the outage.",
			rr.Code)
	}

	// And the cause must not reach the client: HandleFailure writes err.Error()
	// into the response body, so a wrapped driver error hands an unauthenticated
	// caller the address of an internal service.
	if body := rr.Body.String(); strings.Contains(body, "10.0.0.5") || strings.Contains(body, "6379") {
		t.Errorf("the response body %q carries the backend's address to an "+
			"unauthenticated client", body)
	}
}

// TestJWTRejectsRevokedTokens covers the ordinary revoked case.
func TestJWTRejectsRevokedTokens(t *testing.T) {
	c := baseClaims()
	c["jti"] = "token-id-1"
	if got := serveJWT(t, JWTConfig{RevocationStore: revokedStore{}}, mint(t, c)).Code; got != http.StatusUnauthorized {
		t.Errorf("a revoked token got %d, want 401", got)
	}
}

// TestJWTEnforcesScopesAndRoles covers the RBAC leg of validateToken.
func TestJWTEnforcesScopesAndRoles(t *testing.T) {
	cfg := JWTConfig{AuthBaseConfig: AuthBaseConfig{RequiredScopes: []string{"write:orders"}}}

	c := baseClaims()
	c["scope"] = "read:orders write:orders"
	if got := serveJWT(t, cfg, mint(t, c)).Code; got != http.StatusOK {
		t.Errorf("a token holding the required scope got %d, want 200", got)
	}

	c = baseClaims()
	c["scope"] = "read:orders"
	if got := serveJWT(t, cfg, mint(t, c)).Code; got != http.StatusUnauthorized {
		t.Errorf("a token missing the required scope got %d, want 401", got)
	}

	if got := serveJWT(t, cfg, mint(t, baseClaims())).Code; got != http.StatusUnauthorized {
		t.Errorf("a token with no scope claim got %d, want 401", got)
	}
}

// TestJWTDryRunForwardsWithoutAuthenticating records what the flag actually does.
//
// DryRun is an audit-only mode: failures are forwarded rather than refused, so
// an operator can see what a new policy would reject before enforcing it. Worth
// pinning because the flag turns the middleware into a pass-through, and a
// config that reads as "auth is on" while admitting everyone is the exact shape
// of this project's first-run bypass.
func TestJWTDryRunForwardsWithoutAuthenticating(t *testing.T) {
	cfg := JWTConfig{
		Audience:       "api.gateon.internal",
		AuthBaseConfig: AuthBaseConfig{DryRun: true},
	}
	c := baseClaims()
	c["aud"] = "someone.else"

	if got := serveJWT(t, cfg, mint(t, c)).Code; got != http.StatusOK {
		t.Errorf("DryRun got %d, want the request forwarded (200); the mode exists to "+
			"measure a policy before enforcing it", got)
	}
	// And with no credential at all.
	if got := serveJWT(t, cfg, "").Code; got != http.StatusOK {
		t.Errorf("DryRun with no token got %d, want 200 — dry run means every "+
			"failure is forwarded, including a missing credential", got)
	}
}

// TestJWTErrorTemplateReplacesTheReason covers the operator-facing knob.
//
// A custom template is how an operator stops the validator explaining *why* a
// token failed, which otherwise tells an attacker whether they have the issuer
// right, the audience right, or the signature right.
func TestJWTErrorTemplateReplacesTheReason(t *testing.T) {
	cfg := JWTConfig{
		Issuer:         "https://idp.example.com",
		AuthBaseConfig: AuthBaseConfig{ErrorTemplate: "Authentication required"},
	}
	c := baseClaims()
	c["iss"] = "https://evil.example.com"

	rr := serveJWT(t, cfg, mint(t, c))
	body := rr.Body.String()
	if !strings.Contains(body, "Authentication required") {
		t.Errorf("body %q, want the configured template", body)
	}
	if strings.Contains(body, "issuer") {
		t.Errorf("body %q leaks which check failed despite a template being set; "+
			"that tells a caller probing the endpoint how close they are", body)
	}
}

// TestJWTCorsPreflightBypassesAuth covers the one deliberate skip.
//
// A browser sends OPTIONS without credentials by design, so requiring auth on
// the preflight makes every cross-origin call fail before the real request is
// ever sent.
func TestJWTCorsPreflightBypassesAuth(t *testing.T) {
	v, err := NewJWTValidator(JWTConfig{Secret: []byte(testSecret)})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	req := httptest.NewRequest(http.MethodOptions, "/api/resource", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	rr := httptest.NewRecorder()
	v.Handler(okHandler()).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("a CORS preflight got %d, want it forwarded; browsers send OPTIONS "+
			"without credentials, so refusing it breaks every cross-origin call", rr.Code)
	}
}
