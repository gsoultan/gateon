// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTheGlobalConfigSeedIsCopiedOnceOntoAVolumeWithout: the image and chart
// keep global.json on the data volume, where setup can write it, and start it
// from what the operator mounted at /etc/gateon/global.json -- once. A
// global.json the gateway has since written (setup's session key, dashboard
// saves) is never replaced by the seed.
func TestTheGlobalConfigSeedIsCopiedOnceOntoAVolumeWithout(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "etc", "global.json")
	target := filepath.Join(dir, "data", "global.json")
	if err := os.MkdirAll(filepath.Dir(seed), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seed, []byte(`{"redis":{"enabled":true}}`), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv(globalConfigSeedEnv, seed)

	copied, err := seedGlobalConfig(target)
	if err != nil || !copied {
		t.Fatalf("seedGlobalConfig onto an empty volume: copied=%v err=%v", copied, err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != `{"redis":{"enabled":true}}` {
		t.Fatalf("seeded global.json = %q (%v)", got, err)
	}
	if fi, err := os.Stat(target); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("seeded global.json mode = %v (%v), want 0600: it holds the session key once setup runs", fi.Mode().Perm(), err)
	}

	if err := os.WriteFile(target, []byte(`{"auth":{"enabled":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if copied, err := seedGlobalConfig(target); err != nil || copied {
		t.Fatalf("seedGlobalConfig over an existing global.json: copied=%v err=%v", copied, err)
	}
	if got, _ := os.ReadFile(target); string(got) != `{"auth":{"enabled":true}}` {
		t.Errorf("the seed replaced a global.json the gateway wrote: %q", got)
	}
}

// TestNoSeedIsNotAnError: nothing mounted, nothing named, or the seed is the
// file itself -- the gateway starts as before.
func TestNoSeedIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "global.json")
	for _, seed := range []string{"", filepath.Join(dir, "absent.json"), target} {
		t.Setenv(globalConfigSeedEnv, seed)
		if copied, err := seedGlobalConfig(target); err != nil || copied {
			t.Errorf("seed %q: copied=%v err=%v", seed, copied, err)
		}
	}
}

// TestASeedThatCannotBeCopiedIsAnError: starting on the built-in defaults --
// the WAF off -- would drop what the operator mounted.
func TestASeedThatCannotBeCopiedIsAnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through file modes")
	}
	dir := t.TempDir()
	seed := filepath.Join(dir, "global.json.seed")
	if err := os.WriteFile(seed, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Setenv(globalConfigSeedEnv, seed)
	if _, err := seedGlobalConfig(filepath.Join(ro, "global.json")); err == nil {
		t.Error("a seed copied onto an unwritable volume reported success")
	}
}
