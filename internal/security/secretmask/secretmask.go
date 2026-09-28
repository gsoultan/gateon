// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package secretmask says which configuration values are credentials, by name,
// and owns the placeholder the management API shows in their place.
//
// A middleware's config is a map[string]string, and for the auth middlewares the
// values in it are credentials: "secret" for jwt, hmac and pow, "password" and
// "users" for basic auth, "client_secret" for oidc and oauth2. For jwt and hmac
// the value is the signing key for a route the gateway protects, so anyone
// holding it can mint a token the gateway will accept.
//
// Masking and restoring a middleware's secrets is internal/config/mwsecret's
// (ADR 0033); this package is the vocabulary it and the stores share.
package secretmask

import (
	"slices"
	"strings"
)

// Placeholder is what the API returns in place of a stored secret, and what a
// client sends back to keep it.
//
// A fixed, recognisable string rather than an empty one: the dashboard has to be
// able to tell "this middleware has a secret configured" from "this field is
// unset", because those need different screens. It also has to be able to
// recognise the value on the way back, which is why no store accepts it as a
// value (Held).
const Placeholder = "__gateon_redacted__"

// secretKeys are the config keys whose values are credentials.
//
// Listed exactly rather than matched loosely, because the cost of a wrong guess
// runs both ways: masking site_key would break the Turnstile widget, and failing
// to mask client_secret hands out an OIDC identity. The substring rules below
// catch keys added later, and this list is what is true today.
var secretKeys = map[string]bool{
	"secret":        true,
	"secret_key":    true,
	"client_secret": true,
	"password":      true,
	// users is "alice:pw1,bob:pw2" -- every basic-auth password in one string.
	"users":        true,
	"canary_token": true,
}

// publicKeys are keys that the substring rules would otherwise catch but which
// are meant to be read. A site key is printed into the page; a token type hint
// is an OAuth parameter naming a kind, not a token.
var publicKeys = map[string]bool{
	"site_key":          true,
	"public_key":        true,
	"token_type_hint":   true,
	"allow_credentials": true,
}

// IsSecret reports whether a config key holds a credential.
func IsSecret(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if publicKeys[k] {
		return false
	}
	if secretKeys[k] {
		return true
	}
	// Anything added later that is named like a credential is treated as one.
	// Erring towards masking is the right direction: a masked value that did not
	// need masking is a cosmetic problem, and the reverse is this bug again.
	for _, frag := range []string{"secret", "password", "passwd", "passphrase", "private_key", "api_key", "credential"} {
		if strings.Contains(k, frag) {
			return true
		}
	}
	return k == "token" || strings.HasSuffix(k, "_token")
}

// credentialHeaders are the header names that carry a credential whatever
// they are set to.
var credentialHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
}

// credentialFragments are the parts of a header or query-parameter name that
// say its value is a credential: X-Api-Key, X-Auth-Token, X-Session-Id,
// access_token, client_secret, X-Amz-Signature and the like.
var credentialFragments = []string{
	"token", "secret", "passw", "key", "auth", "session", "credential", "signature", "bearer", "jwt",
}

// IsCredentialName reports whether a header or query parameter of this name
// carries a credential, so that a value the headers or rewrite middleware sets
// for it is a secret.
//
// A name is all there is to go on, and it errs towards masking: Sec-WebSocket-Key
// and WWW-Authenticate are caught, which costs an operator a "Stored" badge
// where a value would have done. What it cannot catch is a credential in a
// header whose name gives nothing away (X-Upstream: <token>); ADR 0033 records
// that residue.
func IsCredentialName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if credentialHeaders[n] {
		return true
	}
	for _, frag := range credentialFragments {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}

// Held names every entry of a middleware config whose key or value contains
// Placeholder, sorted. No stored config may hold one: Placeholder is what a
// client sends to keep a stored secret, and stored as a value it would replace
// the credential with a string published in this file -- an HMAC key anyone
// could sign with. The stores refuse such a config and the factory refuses to
// build one, whichever path it came by.
func Held(cfg map[string]string) []string {
	var names []string
	for k, v := range cfg {
		if strings.Contains(k, Placeholder) || strings.Contains(v, Placeholder) {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	return names
}
