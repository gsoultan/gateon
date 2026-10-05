// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package secretmask

import (
	"slices"
	"testing"
)

// TestIsSecretCoversTheCredentialsInUse pins the keys that exist today.
func TestIsSecretCoversTheCredentialsInUse(t *testing.T) {
	for _, k := range []string{
		"secret",        // jwt, hmac, pow, turnstile
		"secret_key",    //
		"client_secret", // oidc
		"password",      // basic auth
		"users",         // basic auth: "alice:pw1,bob:pw2"
		"canary_token",
		// Named like a credential, so masked even though no middleware uses it
		// yet -- a value added later must not have to be remembered here first.
		"api_key", "private_key", "passphrase", "refresh_token", "aws_secret_access_key",
		// Case and spacing are not a way around it.
		"SECRET", " Password ",
	} {
		if !IsSecret(k) {
			t.Errorf("IsSecret(%q) = false; that value is a credential and would be "+
				"returned to anyone allowed to read the config", k)
		}
	}
}

// TestIsSecretLeavesPublicConfigAlone is the other direction.
//
// Over-masking is not free: a Turnstile site key is printed into the page, and
// masking it would break the widget while looking like a security measure.
func TestIsSecretLeavesPublicConfigAlone(t *testing.T) {
	for _, k := range []string{
		"site_key", "public_key", "token_type_hint", "allow_credentials",
		"issuer", "audience", "address", "username", "realm", "header",
		"requests_per_minute", "auth_response_headers",
	} {
		if IsSecret(k) {
			t.Errorf("IsSecret(%q) = true; masking a value that is meant to be read "+
				"breaks the feature it configures", k)
		}
	}
}

// TestIsCredentialNameCoversTheHeadersThatCarryOne: the headers and query
// parameters a gateway sets to authenticate itself upstream, however cased.
func TestIsCredentialNameCoversTheHeadersThatCarryOne(t *testing.T) {
	for _, n := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "apikey",
		"X-Auth-Token", "X-Session-Id", "X-Client-Secret", "X-Password", "X-Amz-Signature",
		"access_token", "api_key", "key", "Bearer", "X-JWT-Assertion", " AUTHORIZATION ",
	} {
		if !IsCredentialName(n) {
			t.Errorf("IsCredentialName(%q) = false; a value set for it is a credential", n)
		}
	}
}

// TestIsCredentialNameLeavesOrdinaryHeadersAlone: a header that carries no
// credential stays readable to a writer, or the headers editor shows nothing.
func TestIsCredentialNameLeavesOrdinaryHeadersAlone(t *testing.T) {
	for _, n := range []string{
		"X-Frame-Options", "Referrer-Policy", "Content-Type", "X-Env", "Cache-Control", "lang", "page",
	} {
		if IsCredentialName(n) {
			t.Errorf("IsCredentialName(%q) = true; its value is no credential", n)
		}
	}
}

// TestIsCredentialNameAllocatesNothing: the telemetry store asks it about every
// header of every trace it keeps, and canonical header names are mixed case.
func TestIsCredentialNameAllocatesNothing(t *testing.T) {
	for _, n := range []string{"Content-Type", "X-Api-Key", "Set-Cookie", "Accept-Language"} {
		if allocs := testing.AllocsPerRun(100, func() { _ = IsCredentialName(n) }); allocs != 0 {
			t.Errorf("IsCredentialName(%q) allocated %v times", n, allocs)
		}
	}
}

// TestHeldNamesEveryEntryHoldingThePlaceholder: in a value, in a key, in part
// of either -- and nothing else.
func TestHeldNamesEveryEntryHoldingThePlaceholder(t *testing.T) {
	cfg := map[string]string{
		"secret":                     Placeholder,
		"users":                      "alice:" + Placeholder,
		"key_" + Placeholder + "_ab": "tenant",
		"issuer":                     "https://idp.example.test",
		"empty":                      "",
	}
	want := []string{"key_" + Placeholder + "_ab", "secret", "users"}
	if got := Held(cfg); !slices.Equal(got, want) {
		t.Errorf("Held = %v, want %v", got, want)
	}
	if got := Held(nil); got != nil {
		t.Errorf("Held(nil) = %v, want nil", got)
	}
}
