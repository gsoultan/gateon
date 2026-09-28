// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mwsecret

import "testing"

// RefAllowed is the host's allow-list for the secret references a middleware
// field may resolve: exact match, read from the environment, empty or unset
// means none.
func TestRefAllowed(t *testing.T) {
	t.Setenv(SecretRefsEnv, " $env:JWT_SECRET , $vault:secret/data/api#key ")
	for _, ref := range []string{"$env:JWT_SECRET", "$vault:secret/data/api#key"} {
		if !RefAllowed(ref) {
			t.Errorf("%q is listed but was refused; whitespace around a listed entry must not matter", ref)
		}
	}
	for _, ref := range []string{"$env:OTHER", "$env:JWT_SECRE", "$env:JWT_SECRET_MORE", "", "  "} {
		if RefAllowed(ref) {
			t.Errorf("%q is not listed but was allowed; the match is exact", ref)
		}
	}
}

func TestRefAllowedUnsetAllowsNothing(t *testing.T) {
	t.Setenv(SecretRefsEnv, "")
	if RefAllowed("$env:ANY") {
		t.Error("with the allow-list unset, a reference was allowed; unset must mean none")
	}
}
