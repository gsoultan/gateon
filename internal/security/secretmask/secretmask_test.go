// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package secretmask

import (
	"maps"
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

// TestConfigDoesNotMutateTheInput is the one that would be a live incident.
//
// The maps handed to Config come straight from the running configuration
// registry. Masking in place would not hide the credential, it would delete it
// -- from the running gateway, on a GET.
func TestConfigDoesNotMutateTheInput(t *testing.T) {
	original := map[string]string{"secret": "real-signing-key", "issuer": "https://idp"}
	before := maps.Clone(original)

	masked := Config(original)

	if !maps.Equal(original, before) {
		t.Fatalf("the input map was modified: %v, was %v.\nThese maps are the live "+
			"configuration, so this does not hide the secret, it destroys it on a "+
			"read request.", original, before)
	}
	if masked["secret"] != Placeholder {
		t.Errorf("secret = %q, want the placeholder", masked["secret"])
	}
	if masked["issuer"] != "https://idp" {
		t.Errorf("issuer = %q, want it untouched", masked["issuer"])
	}
}

// TestConfigLeavesEmptyValuesAlone keeps "unset" distinguishable.
//
// Masking an empty value would make an unconfigured secret look configured, and
// the screen that says "a secret is set" would be lying.
func TestConfigLeavesEmptyValuesAlone(t *testing.T) {
	masked := Config(map[string]string{"secret": ""})
	if masked["secret"] != "" {
		t.Errorf("an empty secret became %q; unset and set must stay distinguishable",
			masked["secret"])
	}
}

func TestConfigHandlesNil(t *testing.T) {
	if got := Config(nil); got != nil {
		t.Errorf("Config(nil) = %v, want nil", got)
	}
}

// TestPreserveKeepsTheStoredSecret is what stops masking from breaking saves.
//
// The dashboard reads a middleware, shows the mask, an operator renames it and
// saves. Without this the placeholder is written over the real credential and
// the route's authentication breaks, from an edit that never touched it.
func TestPreserveKeepsTheStoredSecret(t *testing.T) {
	stored := map[string]string{"secret": "real-signing-key", "issuer": "https://idp"}
	incoming := map[string]string{"secret": Placeholder, "issuer": "https://idp2"}

	merged := Preserve(incoming, stored)

	if merged["secret"] != "real-signing-key" {
		t.Errorf("secret = %q, want the stored value kept. An edit that did not touch "+
			"the credential would otherwise overwrite it with the placeholder.",
			merged["secret"])
	}
	if merged["issuer"] != "https://idp2" {
		t.Errorf("issuer = %q, want the new value; only the placeholder is special",
			merged["issuer"])
	}
}

// TestPreserveAcceptsARealChange covers rotating a secret.
func TestPreserveAcceptsARealChange(t *testing.T) {
	merged := Preserve(
		map[string]string{"secret": "a-new-key"},
		map[string]string{"secret": "the-old-key"},
	)
	if merged["secret"] != "a-new-key" {
		t.Errorf("secret = %q, want the new value; a caller must be able to rotate "+
			"a credential", merged["secret"])
	}
}

// TestPreserveDropsAPlaceholderWithNothingBehindIt covers the odd case.
//
// The placeholder arriving for a key that has no stored value means something
// went wrong upstream. Writing it literally would set the credential to a
// publicly known string, which is worse than leaving it unset.
func TestPreserveDropsAPlaceholderWithNothingBehindIt(t *testing.T) {
	merged := Preserve(map[string]string{"secret": Placeholder}, map[string]string{})
	if v, ok := merged["secret"]; ok {
		t.Errorf("secret = %q; the placeholder is a known string and must never "+
			"become the credential", v)
	}

	merged = Preserve(map[string]string{"secret": Placeholder}, nil)
	if v := merged["secret"]; v == Placeholder {
		t.Error("with no stored config the placeholder was written through as the " +
			"credential")
	}
}

// TestPreserveHandlesNil covers a delete-all-config save.
func TestPreserveHandlesNil(t *testing.T) {
	if got := Preserve(nil, map[string]string{"secret": "x"}); got != nil {
		t.Errorf("Preserve(nil, ...) = %v, want nil so an explicit clear still clears", got)
	}
}
