// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package testutil

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// TestMintWithIDSetsTheTokenID pins what a revocation test relies on: the ID
// it asks for is the token's jti, and Mint carries none.
func TestMintWithIDSetsTheTokenID(t *testing.T) {
	p := NewFakeOIDCProvider(t, "client")
	for _, tc := range []struct{ id, want string }{{"revoked-1", "revoked-1"}, {"", ""}} {
		tok, err := p.MintWithID("alice", tc.id)
		if err != nil {
			t.Fatal(err)
		}
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(tok, claims); err != nil {
			t.Fatal(err)
		}
		got, _ := claims["jti"].(string)
		if got != tc.want {
			t.Errorf("MintWithID(%q): jti = %q, want %q", tc.id, got, tc.want)
		}
		if claims["sub"] != "alice" || claims["aud"] != "client" {
			t.Errorf("MintWithID(%q): sub/aud = %v/%v", tc.id, claims["sub"], claims["aud"])
		}
	}
}
