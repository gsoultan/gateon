// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mwsecret

import "testing"

// IsSecretField is what the factory asks before it resolves a secret reference:
// a reference is honoured only in a field that holds a secret, never in one
// whose value is merely echoed to the client.
func TestIsSecretField(t *testing.T) {
	secret := []struct{ mwType, key string }{
		{"hmac", "secret"},
		{"auth", "secret"},
		{"apikey", "key_tenant-a"},
		{"auth", "users"},
		{"headers", "set_response_Authorization"},
		{"headers", "add_request_X-Api-Key"},
	}
	for _, c := range secret {
		if !IsSecretField(c.mwType, c.key) {
			t.Errorf("IsSecretField(%q, %q) = false, want true", c.mwType, c.key)
		}
	}
	plain := []struct{ mwType, key string }{
		{"headers", "set_response_X-Frame-Options"},
		{"rewrite", "query_page"},
		{"auth", "type"},
		{"ratelimit", "average"},
	}
	for _, c := range plain {
		if IsSecretField(c.mwType, c.key) {
			t.Errorf("IsSecretField(%q, %q) = true, want false", c.mwType, c.key)
		}
	}
}
