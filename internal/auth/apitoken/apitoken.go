// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package apitoken issues and checks the long-lived, scoped credentials an
// administrator gives a machine. See ADR 0050.
//
// /metrics accepted only a user's eight-hour session, so a Prometheus server
// needed a viewer account, its password on disk, and a timer re-signing in
// every few hours. A token here is issued once, does only what its scopes say
// (today: read /metrics), and is revoked by deleting it. Only a SHA-256 of
// the token is stored: it is 256 random bits, so a slow hash adds nothing and
// a fast one keeps a scrape to one indexed lookup. The secret is returned once,
// by Create, and never again.
//
// A token is never a session. PasetoAuth does not know this format, so every
// path but the ones that ask for a scope here refuses it, and the proxy
// withholds anything shaped like one from every backend.
package apitoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"
)

// Scope is one thing a token may do.
type Scope string

// ScopeMetricsRead lets a token read GET /metrics on the management plane.
const ScopeMetricsRead Scope = "metrics:read"

// Scopes are the scopes a token may be issued with. Every one is read-only.
var Scopes = []Scope{ScopeMetricsRead}

// Prefix starts every token, so a leaked one is recognisable in a log or a
// repository scan, and so the proxy can withhold one without a lookup.
const Prefix = "gateon_tok_"

// secretBytes is the token's entropy: 256 bits.
const secretBytes = 32

// encodedLen is the length of a token: the prefix and 32 bytes of unpadded
// base64url.
var encodedLen = len(Prefix) + base64.RawURLEncoding.EncodedLen(secretBytes)

// MaxActive is how many tokens may exist at once. A scrape credential per
// scraper is a handful; the cap keeps the list one page and the table small.
const MaxActive = 50

// MaxNameLength bounds a token's name.
const MaxNameLength = 64

// MaxTTLDays bounds an expiry; 0 is no expiry.
const MaxTTLDays = 3650

var (
	// ErrInvalid answers every refused token the same way: unknown, expired,
	// revoked, malformed, or without the scope asked for.
	ErrInvalid = errors.New("api token not accepted")
	// ErrNotFound refuses a revocation of a token that does not exist.
	ErrNotFound = errors.New("api token not found")
	// ErrTooMany refuses a token past MaxActive.
	ErrTooMany = errors.New("too many api tokens; revoke one first")
	// ErrBadRequest wraps every refusal of a malformed Create.
	ErrBadRequest = errors.New("invalid api token request")
)

// Token is a stored token, without its secret.
type Token struct {
	ID         string
	Name       string
	Scopes     []Scope
	Hint       string
	CreatedBy  string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero when never used
	ExpiresAt  time.Time // zero when it does not expire
}

// Allows reports whether the token carries scope.
func (t Token) Allows(scope Scope) bool { return slices.Contains(t.Scopes, scope) }

// Expired reports whether the token has expired at now.
func (t Token) Expired(now time.Time) bool { return !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt) }

// LooksLikeToken reports whether s has a token's shape: the prefix, the
// length, and only base64url characters. It reads nothing and allocates
// nothing, which is what lets the proxy call it on every request.
func LooksLikeToken(s string) bool {
	if len(s) != encodedLen || !strings.HasPrefix(s, Prefix) {
		return false
	}
	for i := len(Prefix); i < len(s); i++ {
		c := s[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// BearerToken returns the token in an "Authorization: Bearer <token>" value,
// when it has a token's shape.
func BearerToken(header string) (string, bool) {
	const scheme = "bearer "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	token := strings.TrimSpace(header[len(scheme):])
	return token, LooksLikeToken(token)
}

// newSecret returns a fresh token and its stored hash.
func newSecret() (secret, hash string, err error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret = Prefix + base64.RawURLEncoding.EncodeToString(b)
	return secret, hashOf(secret), nil
}

func hashOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// hintOf is what the list shows of a token: the prefix and four characters.
func hintOf(secret string) string { return secret[:len(Prefix)+4] + "…" }

// ParseScopes keeps the known scopes in s, in order, without repeats, and
// reports whether every entry was known.
func ParseScopes(s []string) ([]Scope, bool) {
	out := make([]Scope, 0, len(s))
	for _, raw := range s {
		sc := Scope(strings.TrimSpace(raw))
		if !slices.Contains(Scopes, sc) {
			return nil, false
		}
		if !slices.Contains(out, sc) {
			out = append(out, sc)
		}
	}
	return out, len(out) > 0
}

func joinScopes(s []Scope) string {
	parts := make([]string, len(s))
	for i, sc := range s {
		parts[i] = string(sc)
	}
	return strings.Join(parts, ",")
}

func splitScopes(s string) []Scope {
	var out []Scope
	for part := range strings.SplitSeq(s, ",") {
		if part != "" {
			out = append(out, Scope(part))
		}
	}
	return out
}
