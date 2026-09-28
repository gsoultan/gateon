// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package mwsecret keeps middleware credentials on the gateway's side of the
// management API, as storedsecret does for the global configuration. See
// ADR 0033.
//
// Nothing the API returns carries a stored middleware secret, to anyone. A
// caller who may write middlewares reads each secret as storedsecret.Sentinel,
// a reference ($env:, $vault:, $aws-sm:) as the reference, and an unset one as
// "", and sends Sentinel back to keep it. A caller who may only read reads
// Sentinel for every secret, reference or not, and for every value the headers
// and rewrite middlewares set.
package mwsecret

import (
	"errors"
	"strings"

	"github.com/gsoultan/gateon/internal/config/storedsecret"
	"github.com/gsoultan/gateon/internal/security/secretmask"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Sentinel is the placeholder the API returns for a stored secret and a
// client sends back to keep it; the global configuration uses the same one.
const Sentinel = storedsecret.Sentinel

var (
	// ErrNotASecret refuses Sentinel in a field that holds no secret: there is
	// nothing it could stand for.
	ErrNotASecret = errors.New("the stored-secret placeholder stands for a stored secret, and this field holds " +
		"none; send its value")
	// ErrNewMiddleware refuses Sentinel in a middleware no stored one has the id
	// of: a placeholder keeps a stored secret, and there is none.
	ErrNewMiddleware = errors.New("no stored middleware has this id, so there is no stored secret to keep; " +
		"enter the values")
	// ErrTypeChanged refuses Sentinel when the update changes what kind of
	// middleware this is: a secret is kept only for the use it was entered for.
	ErrTypeChanged = errors.New("the stored secrets were entered for another kind of middleware; enter them again")
)

// kind is what a config entry holds, as far as secrets go.
type kind int

const (
	plain    kind = iota // not a secret
	scalar               // the value is a secret
	userList             // basic-auth users, "name:password,..."
	keyName              // the key's suffix is the secret: the apikey middleware's "key_<APIKEY>"
)

// apiKeyPrefix marks config keys whose suffix is an API key the apikey
// middleware accepts; the value is the tenant label.
const apiKeyPrefix = "key_"

// usersKey is the basic-auth middleware's user list.
const usersKey = "users"

// IsSecretField reports whether the entry key holds a secret in a middleware of
// type mwType: a scalar secret, a basic-auth user list, an API key, or a
// header or query value set under a credential name. The factory asks before it
// resolves a $env:/$vault:/$aws-sm: reference, so a reference is refused in a
// field that holds no secret -- where its resolved value would only be echoed
// back, never used as a credential.
func IsSecretField(mwType, key string) bool {
	return classify(mwType, key) != plain
}

// classify says what the entry key holds in a middleware of type mwType, for a
// caller who may write it.
func classify(mwType, key string) kind {
	if suffix, ok := strings.CutPrefix(key, apiKeyPrefix); ok && suffix != "" {
		return keyName
	}
	if key == usersKey {
		return userList
	}
	if secretmask.IsSecret(key) {
		return scalar
	}
	if name, ok := setName(mwType, key); ok && secretmask.IsCredentialName(name) {
		return scalar
	}
	return plain
}

// headerPrefixes are the headers middleware's settings that carry a value;
// del_ settings name a header and set nothing.
var headerPrefixes = []string{"add_request_", "set_request_", "add_response_", "set_response_"}

// setName is the header or query-parameter name a headers or rewrite
// middleware setting sets, and whether key is such a setting.
func setName(mwType, key string) (string, bool) {
	switch mwType {
	case "headers":
		for _, p := range headerPrefixes {
			if name, ok := strings.CutPrefix(key, p); ok && name != "" {
				return name, true
			}
		}
	case "rewrite":
		if name, ok := strings.CutPrefix(key, "query_"); ok && name != "" {
			return name, true
		}
	}
	return "", false
}

// upstreamRequestPrefixes are the headers-middleware settings that add a header
// to the request the gateway forwards to the backend. The response-direction
// settings (add_response_/set_response_) are deliberately excluded: their value
// travels to the downstream client, not to the route's backend, so they are not
// a credential injected "toward the backend" and blocking them would refuse an
// operator legitimately setting a Set-Cookie on a response. ADR 0038 records
// that as residue.
var upstreamRequestPrefixes = []string{"add_request_", "set_request_"}

// upstreamSetName is the header or query-parameter name a headers or rewrite
// middleware setting sends toward the backend, and whether key is such a
// setting. It is setName restricted to the request/upstream direction.
func upstreamSetName(mwType, key string) (string, bool) {
	switch mwType {
	case "headers":
		for _, p := range upstreamRequestPrefixes {
			if name, ok := strings.CutPrefix(key, p); ok && name != "" {
				return name, true
			}
		}
	case "rewrite":
		if name, ok := strings.CutPrefix(key, "query_"); ok && name != "" {
			return name, true
		}
	}
	return "", false
}

// InjectsCredentialUpstream reports whether mw, as it is configured now, sends a
// credential to the backend a route using it points at: a headers middleware
// that sets or adds a request header under a credential name, or a rewrite
// middleware that adds a query parameter under one, with a non-empty value.
//
// This is the shape ADR 0033 left as residue -- a stored Authorization or
// X-Api-Key value the middleware delivers upstream -- and it is what ADR 0038
// uses to decide that binding such a middleware to a route needs an
// administrator, because an operator could otherwise point the route at a
// backend they run and read the value. It classifies by the resolved config
// shape only; the value's origin (a literal, an enc: value or a reference) does
// not matter, because all three reach the backend the same way. Its residue is
// the same name-based blind spot secretmask.IsCredentialName has: a credential
// under a header name that gives nothing away (X-Upstream: <token>) is not
// recognised, and a credential set on a response header is out of scope because
// it does not travel to the backend.
func InjectsCredentialUpstream(mw *gateonv1.Middleware) bool {
	if mw == nil {
		return false
	}
	mwType := strings.ToLower(strings.TrimSpace(mw.GetType()))
	if mwType != "headers" && mwType != "rewrite" {
		return false
	}
	for k, v := range mw.GetConfig() {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if name, ok := upstreamSetName(mwType, k); ok && secretmask.IsCredentialName(name) {
			return true
		}
	}
	return false
}

// identity is what a kept secret is bound to besides the middleware's id: its
// type, and for the auth middleware the kind of authentication, since that
// decides what the secret is used for.
func identity(mw *gateonv1.Middleware) string {
	if mw.GetType() == "auth" {
		return "auth/" + strings.TrimSpace(mw.GetConfig()["type"])
	}
	return mw.GetType()
}

// destinationKey is the config entry naming where the middleware sends its
// secrets, when the configuration chooses that: the token introspection
// endpoint the client secret authenticates to, the OpenID provider the client
// secret is sent to, the forward-auth service. "" when the secrets stay in the
// gateway or go to a fixed address (Cloudflare's siteverify for turnstile).
func destinationKey(mw *gateonv1.Middleware) string {
	switch identity(mw) {
	case "auth/oauth2", "auth/oauth2_introspection":
		return "introspection_url"
	case "oidc":
		return "issuer"
	case "forwardauth":
		return "address"
	}
	return ""
}
