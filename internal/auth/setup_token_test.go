// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupTokenIsRandomUnlessTheOperatorSuppliedOne(t *testing.T) {
	a, err := NewSetupToken("")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSetupToken("")
	if err != nil {
		t.Fatal(err)
	}
	if a.Value() == b.Value() || len(a.Value()) < 43 {
		t.Errorf("generated tokens %q and %q: want two different values of 32 random bytes", a.Value(), b.Value())
	}
	if a.FromEnv() {
		t.Error("a generated token reports that the operator supplied it")
	}

	supplied := strings.Repeat("s", minSetupTokenLen)
	c, err := NewSetupToken(supplied)
	if err != nil || c.Value() != supplied || !c.FromEnv() {
		t.Errorf("NewSetupToken(%q) = %q, fromEnv %v, err %v", supplied, c.Value(), c.FromEnv(), err)
	}
	if _, err := NewSetupToken("short"); !errors.Is(err, ErrSetupTokenTooShort) {
		t.Errorf("a guessable GATEON_SETUP_TOKEN was accepted: err = %v", err)
	}
}

// Setup stays closed rather than open when the token is missing, wrong,
// retired, or was never wired in.
func TestSetupTokenMatchesOnlyItself(t *testing.T) {
	tok, err := NewSetupToken("")
	if err != nil {
		t.Fatal(err)
	}
	if !tok.Matches(tok.Value()) {
		t.Fatal("the token does not match itself")
	}
	for _, got := range []string{"", "wrong", tok.Value() + "x", tok.Value()[1:]} {
		if tok.Matches(got) {
			t.Errorf("Matches(%q) = true", got)
		}
	}
	var none *SetupToken
	if none.Matches("") || none.Matches("anything") {
		t.Error("a nil token matched")
	}
	value := tok.Value()
	tok.Retire()
	if tok.Matches(value) {
		t.Error("a retired token still matches")
	}
}

func TestSetupTokenFileIsTheGatewaysAloneAndGoesWithIt(t *testing.T) {
	dir := t.TempDir()
	tok, err := NewSetupToken("")
	if err != nil {
		t.Fatal(err)
	}
	// Whatever an earlier run left at the name -- a file readable by others,
	// or a link to somewhere else -- is replaced, not written through.
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(elsewhere, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, SetupTokenFile)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	path, err := tok.Publish(dir)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Errorf("setup token file mode = %v, want a regular file readable by the gateway alone", info.Mode())
	}
	if got, _ := os.ReadFile(path); strings.TrimSpace(string(got)) != tok.Value() {
		t.Errorf("setup token file holds %q, want the token", got)
	}
	if got, _ := os.ReadFile(elsewhere); string(got) != "untouched" {
		t.Errorf("Publish wrote through the link it found: %s now holds %q", elsewhere, got)
	}

	tok.Retire()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the setup token file outlived setup (stat err = %v)", err)
	}
}
