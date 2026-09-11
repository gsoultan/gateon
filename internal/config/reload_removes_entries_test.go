// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Both file-backed registries used to merge a read into whatever was already
// loaded, so a second read could add and change but never remove. A route
// deleted from routes.json kept being served; a setting deleted from
// global.json stayed in force. Neither logged anything, because the only
// evidence was an entry that failed to disappear.
//
// This is latent rather than live: load() is called once, from the constructor,
// and there is no file watcher, no SIGHUP handler and no reload endpoint --
// fsnotify is not a dependency at all. So replace and merge are identical
// today, which is exactly why this was worth changing now rather than after
// someone adds a watcher and inherits both bugs at once.
//
// These call load() twice directly, which is the thing production does not do.

func TestGlobalConfigReloadRevertsARemovedKeyToItsDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "global.json")

	if err := os.WriteFile(path, []byte(`{"management":{"allowed_ips":["10.0.0.0/8"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := NewGlobalRegistry(path)
	if got := reg.config.Load().GetManagement().GetAllowedIps(); len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("first load: allowed_ips = %v, want [10.0.0.0/8]", got)
	}

	// The operator removes the restriction from the file.
	if err := os.WriteFile(path, []byte(`{"management":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg.load()

	got := reg.config.Load().GetManagement().GetAllowedIps()
	if len(got) == 1 && got[0] == "10.0.0.0/8" {
		t.Fatal("a value deleted from global.json survived the reload; " +
			"an operator editing the file to remove a setting sees no effect")
	}
	// It reverts to the shipped default rather than to nothing, because the
	// read starts from the defaults snapshot.
	if len(got) != 2 || got[0] != "0.0.0.0/0" {
		t.Fatalf("allowed_ips = %v, want the shipped default [0.0.0.0/0 ::/0]", got)
	}
}

// The defaults snapshot must be stable across reads. It carries a per-install
// proof-of-work secret, and regenerating it would invalidate every challenge in
// flight — so the snapshot is taken once rather than rebuilt.
func TestGlobalConfigReloadKeepsThePerInstallPowSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "global.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := NewGlobalRegistry(path)

	first := reg.config.Load().GetSecurityAdvanced().GetPow().GetSecret()
	if first == "" {
		t.Fatal("no proof-of-work secret was generated")
	}
	reg.load()
	if second := reg.config.Load().GetSecurityAdvanced().GetPow().GetSecret(); second != first {
		t.Fatal("the proof-of-work secret changed across a reload, " +
			"which invalidates every challenge already issued")
	}
}

func TestRouteReloadDropsARouteRemovedFromTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")

	if err := os.WriteFile(path, []byte(
		`[{"id":"keep","rule":"Host(`+"`a.example.com`"+`)"},`+
			`{"id":"remove-me","rule":"Host(`+"`b.example.com`"+`)"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := NewRouteRegistry(path)
	if n := len(reg.routes); n != 2 {
		t.Fatalf("first load: %d routes, want 2", n)
	}

	// The operator deletes one route from the file.
	if err := os.WriteFile(path, []byte(
		`[{"id":"keep","rule":"Host(`+"`a.example.com`"+`)"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg.load()

	if _, still := reg.routes["remove-me"]; still {
		t.Fatal("a route deleted from routes.json survived the reload; " +
			"the gateway would keep serving it until restart")
	}
	if _, ok := reg.routes["keep"]; !ok {
		t.Fatal("the surviving route was dropped; replace must not lose what the file still lists")
	}
}
