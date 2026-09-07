// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package secretmask hides credentials in configuration that is being read back.
//
// A middleware's config is a map[string]string, and for the auth middlewares the
// values in it are credentials: "secret" for jwt, hmac and pow, "password" and
// "users" for basic auth, "client_secret" for oidc. The list and get endpoints
// returned those maps as stored, and RoleViewer -- the lowest role there is,
// read-only by definition -- holds ActionRead on ResourceMiddlewares.
//
// That is not a configuration disclosure. For jwt and hmac the value is the
// signing key for a route the gateway is protecting, so anyone holding it can
// mint a token the gateway will accept. A read-only dashboard account became
// access to the backend as any user.
package secretmask

import "strings"

// Placeholder is what a masked value is replaced with.
//
// A fixed, recognisable string rather than an empty one: the dashboard has to be
// able to tell "this middleware has a secret configured" from "this field is
// unset", because those need different screens. It also has to be able to
// recognise the value on the way back -- see Preserve.
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

// Config returns a copy of cfg with every credential replaced by Placeholder.
//
// A copy, always. The maps handed to this come straight from the live
// configuration registry, and masking in place would not hide the secret -- it
// would delete it, from the running gateway, on a GET.
func Config(cfg map[string]string) map[string]string {
	if cfg == nil {
		return nil
	}
	out := make(map[string]string, len(cfg))
	for k, v := range cfg {
		if v != "" && IsSecret(k) {
			out[k] = Placeholder
			continue
		}
		out[k] = v
	}
	return out
}

// Preserve merges an incoming config over a stored one, keeping the stored value
// wherever the caller sent the placeholder back.
//
// Without this, masking breaks the thing it protects. The dashboard reads a
// middleware, shows the mask, an operator edits the name and saves -- and the
// placeholder is written over the real secret, so the credential is destroyed by
// an edit that had nothing to do with it. Masking a value on the way out means
// recognising it on the way back in.
func Preserve(incoming, stored map[string]string) map[string]string {
	if incoming == nil {
		return nil
	}
	out := make(map[string]string, len(incoming))
	for k, v := range incoming {
		if v == Placeholder {
			// Reading a nil map is fine and returns not-found, which is the
			// case that matters: if there is no stored value behind the
			// placeholder the key is dropped rather than written through.
			// Writing it literally would set the credential to a string
			// published in this file, which is worse than leaving it unset.
			if prev, ok := stored[k]; ok {
				out[k] = prev
			}
			continue
		}
		out[k] = v
	}
	return out
}
