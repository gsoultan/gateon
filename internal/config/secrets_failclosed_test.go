// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const unsetSecretVar = "GATEON_TEST_UNSET_SECRET_7731"

// TestUnresolvableReferenceIsNeverTheSecret resolves a reference to a variable
// nobody set. The chain used to hand the reference back with a nil error, so
// "$vault:..." with Vault down became the JWT signing secret, and an unresolved
// database_url opened a SQLite file named after the reference.
func TestUnresolvableReferenceIsNeverTheSecret(t *testing.T) {
	if _, set := os.LookupEnv(unsetSecretVar); set {
		t.Fatalf("precondition: %s must be unset", unsetSecretVar)
	}
	ref := "$env:" + unsetSecretVar
	got, err := ResolveSecretStrict(ref)
	if err == nil {
		t.Fatalf("resolved %q to %q with no error", ref, got)
	}
	if got == ref {
		t.Fatal("the reference itself was returned as the secret")
	}
}

// TestPlainValuesAndResolvableReferencesStillResolve keeps the fix from
// refusing what always worked: a literal passes through untouched, and a set
// variable resolves to its value.
func TestPlainValuesAndResolvableReferencesStillResolve(t *testing.T) {
	t.Setenv("GATEON_TEST_SET_SECRET_7731", "s3cret")
	for in, want := range map[string]string{
		"literal-secret":                      "literal-secret",
		"":                                    "",
		"$env:GATEON_TEST_SET_SECRET_7731":    "s3cret",
		"not$env:GATEON_TEST_SET_SECRET_7731": "not$env:GATEON_TEST_SET_SECRET_7731",
	} {
		got, err := ResolveSecretStrict(in)
		if err != nil || got != want {
			t.Errorf("ResolveSecretStrict(%q) = %q, %v; want %q, nil", in, got, err, want)
		}
	}
}

// TestChainSkipsResolversThatCouldNotBeBuilt resolves a vault reference
// through a chain holding a nil resolver, which is what a failed Vault or AWS
// constructor used to leave there. The first reference to reach it was a
// nil-interface call -- a panic at boot on Linux, a silent hang on macOS.
func TestChainSkipsResolversThatCouldNotBeBuilt(t *testing.T) {
	chain := &ChainSecretResolver{resolvers: []SecretResolver{&EnvSecretResolver{}, nil}}
	done := make(chan error, 1)
	go func() {
		_, err := chain.Resolve("$vault:secret/data/api#jwt")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("resolved a vault reference with no vault resolver in the chain")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("resolving through a chain holding a nil resolver never returned")
	}
}

// TestDefaultResolverReportsAResolverThatFailedToBuild breaks the Vault
// client's environment, as a mistyped VAULT_SKIP_VERIFY does. The chain must
// hold no nil, and a vault reference must fail saying why.
func TestDefaultResolverReportsAResolverThatFailedToBuild(t *testing.T) {
	t.Setenv("VAULT_SKIP_VERIFY", "not-a-bool")
	chain := newDefaultResolver()
	for i, r := range chain.resolvers {
		if r == nil {
			t.Fatalf("resolver %d is nil", i)
		}
	}
	_, err := chain.Resolve("$vault:secret/data/api#jwt")
	if err == nil || !strings.Contains(err.Error(), "vault resolver unavailable") {
		t.Fatalf("got %v, want an error naming the unavailable vault resolver", err)
	}
}

// TestGlobalConfigWithAnUnresolvableSecretDoesNotLoad reads a global.json whose
// database URL names an unset variable. Loading must fail -- startup refuses on
// LoadErr -- rather than serve on the reference's own text.
func TestGlobalConfigWithAnUnresolvableSecretDoesNotLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "global.json")
	body := `{"auth": {"enabled": true, "database_url": "$env:` + unsetSecretVar + `"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := NewGlobalRegistry(path)
	if reg.LoadErr() == nil {
		t.Fatalf("loaded with auth.database_url = %q", reg.Get(t.Context()).GetAuth().GetDatabaseUrl())
	}
}
