// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import "testing"

// TestEnvSecretResolverDistinguishesUnsetFromEmpty covers a silent
// misresolution with an expensive tail.
//
// An unset or misspelled variable used to resolve to "" with a nil error, and
// ChainSecretResolver accepts any resolution that differs from its input -- so
// "$env:GATEON_DB_URL" for a variable nobody exported became the empty string.
// decryptSensitiveFields runs this over Auth.DatabaseUrl and
// Auth.PasetoSecret, and an empty database URL sends db.AuthDatabaseURL to its
// "gateon.db" fallback: a Postgres-backed install silently comes up on a local
// SQLite file, with a Paseto secret that bootstrap regenerates every restart.
func TestEnvSecretResolverDistinguishesUnsetFromEmpty(t *testing.T) {
	r := &EnvSecretResolver{}

	t.Run("unset is an error, not an empty string", func(t *testing.T) {
		got, err := r.Resolve("$env:GATEON_DEFINITELY_NOT_SET_12345")
		if err == nil {
			t.Errorf("Resolve returned %q with no error for an unset variable; "+
				"the caller substitutes it and cannot tell", got)
		}
	})

	t.Run("deliberately empty is honoured", func(t *testing.T) {
		t.Setenv("GATEON_TEST_EMPTY_SECRET", "")
		got, err := r.Resolve("$env:GATEON_TEST_EMPTY_SECRET")
		if err != nil {
			t.Errorf("Resolve errored for a variable that is set but empty: %v; "+
				"an operator who set it deliberately is entitled to that", err)
		}
		if got != "" {
			t.Errorf("Resolve = %q, want empty", got)
		}
	})

	t.Run("a set variable resolves", func(t *testing.T) {
		t.Setenv("GATEON_TEST_SECRET", "s3cret")
		got, err := r.Resolve("$env:GATEON_TEST_SECRET")
		if err != nil || got != "s3cret" {
			t.Errorf("Resolve = (%q, %v), want (\"s3cret\", nil)", got, err)
		}
	})

	t.Run("a plain value passes through", func(t *testing.T) {
		got, err := r.Resolve("not-a-reference")
		if err != nil || got != "not-a-reference" {
			t.Errorf("Resolve = (%q, %v), want it unchanged", got, err)
		}
	})
}
