// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// A configured gateway's global.json with one mistake in it: management.port
// is a string field and this writes a number. encoding/json reports that and
// the registry gave up on the whole file.
const globalJSONWithOneMistake = `{
  "waf": {"enabled": true, "paranoia_level": 3},
  "auth": {"enabled": true, "database_url": "postgres://gateon:pw@db.internal/gateon"},
  "management": {"bind": "10.0.0.5", "port": 9443, "allowed_ips": ["10.0.0.0/8"]}
}`

// TestGlobalRegistryDoesNotOverwriteAFileItCouldNotParse is the startup
// sequence against that file.
//
// The registry fell back to the built-in defaults -- WAF off, management open to
// every address, no auth database -- and the bootstrap in internal/inits, seeing
// no auth database, filled one in and wrote the result back. So the operator's
// file was replaced, at boot, by defaults: the WAF settings, the Postgres DSN and
// the allowlist were gone from disk, and correcting the typo afterwards had
// nothing left to correct.
func TestGlobalRegistryDoesNotOverwriteAFileItCouldNotParse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "global.json")
	if err := os.WriteFile(path, []byte(globalJSONWithOneMistake), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := NewGlobalRegistry(path)

	// What inits.InitGlobalConfig does with the registry on every start: read
	// the config, fill in the auth defaults it finds missing, write it back.
	gc := reg.Get(context.Background())
	gc.Auth = &gateonv1.AuthConfig{PasetoSecret: GenerateRandomSecret(32)}
	updateErr := reg.Update(context.Background(), gc)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(globalJSONWithOneMistake)) {
		t.Fatalf("the operator's global.json was replaced by the defaults the registry fell back to "+
			"(update error: %v); on disk now:\n%s", updateErr, got)
	}
	if updateErr == nil {
		t.Error("Update reported success for a write it must not make")
	}
}

// TestGlobalRegistryReportsWhyItCouldNotLoad pins the signal startup refuses on,
// and that neither a good file nor an absent one -- the first run, which reaches
// the setup wizard through it -- produces it.
func TestGlobalRegistryReportsWhyItCouldNotLoad(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(bad, []byte(globalJSONWithOneMistake), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, []byte(`{"waf": {"enabled": true}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := NewGlobalRegistry(bad).LoadErr(); err == nil {
		t.Error("a file that could not be parsed reported no load error")
	}
	if err := NewGlobalRegistry(good).LoadErr(); err != nil {
		t.Errorf("a good file reported %v", err)
	}
	if err := NewGlobalRegistry(filepath.Join(dir, "absent.json")).LoadErr(); err != nil {
		t.Errorf("an absent file -- the first run -- reported %v", err)
	}
}
