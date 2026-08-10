// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package config

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestPowSecretIsNeverThePublishedPlaceholder covers the bug where the shipped
// default proof-of-work secret was the literal "changeme".
//
// Root cause: the PoW challenge and its accepted solution are both HMACs keyed
// on this value, so a constant in the repository is a published key. An
// operator who enabled bot challenges without setting a secret got a control
// that reported "protected" while any attacker who read the source could mint
// valid solutions offline.
func TestPowSecretIsNeverThePublishedPlaceholder(t *testing.T) {
	t.Run("fresh install generates a unique secret", func(t *testing.T) {
		dir := t.TempDir()
		a := NewGlobalRegistry(dir + "/a.json")
		b := NewGlobalRegistry(dir + "/b.json")

		secretA := a.Get(t.Context()).GetSecurityAdvanced().GetPow().GetSecret()
		secretB := b.Get(t.Context()).GetSecurityAdvanced().GetPow().GetSecret()

		if IsPlaceholderPowSecret(secretA) {
			t.Fatalf("fresh install shipped a placeholder PoW secret: %q", secretA)
		}
		if secretA == secretB {
			t.Error("two installs generated the same PoW secret; it must be per-install")
		}
		if len(secretA) < 16 {
			t.Errorf("PoW secret too short to be a useful HMAC key: %d chars", len(secretA))
		}
	})

	t.Run("placeholder is recognised", func(t *testing.T) {
		for _, s := range []string{"changeme", "CHANGEME", " changeme ", "", "   "} {
			if !IsPlaceholderPowSecret(s) {
				t.Errorf("IsPlaceholderPowSecret(%q) = false, want true", s)
			}
		}
		if IsPlaceholderPowSecret("f3a9c1d0e7b28451") {
			t.Error("a real secret was treated as a placeholder")
		}
	})

	t.Run("an existing install carrying the placeholder is re-keyed on load", func(t *testing.T) {
		cfg := &gateonv1.GlobalConfig{
			SecurityAdvanced: &gateonv1.SecurityAdvancedConfig{
				Pow: &gateonv1.PowConfig{Secret: DefaultPowSecret},
			},
		}
		decryptSensitiveFields(cfg)

		got := cfg.GetSecurityAdvanced().GetPow().GetSecret()
		if IsPlaceholderPowSecret(got) {
			t.Errorf("placeholder survived load: %q — installs created before the fix stay exploitable", got)
		}
	})
}
