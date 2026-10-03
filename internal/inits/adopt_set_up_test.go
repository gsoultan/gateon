// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package inits

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// bootSeeded starts a gateway the way a pod on a fresh volume does: global.json
// is the chart's seed, naming dbPath and nothing setup writes.
func bootSeeded(t *testing.T, dbPath string) (*config.GlobalRegistry, *auth.Manager, string) {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	t.Setenv(config.SessionKeyEnv, "seeded-session-key-0123456789abc")
	path := filepath.Join(t.TempDir(), "global.json")
	seed := fmt.Sprintf(`{"audit": {"enabled": true, "sign_entries": true}, "auth": {"database_url": %q}}`, dbPath)
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := config.NewGlobalRegistry(path)
	m := InitGlobalConfig(path, reg)
	if m == nil {
		t.Fatal("startup built no auth manager")
	}
	t.Cleanup(func() { _ = m.Close() })
	return reg, m, path
}

func storedAuthEnabled(t *testing.T, path string) bool {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Auth struct {
			Enabled bool `json:"enabled"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	return stored.Auth.Enabled
}

// TestASeededStartOverASetUpDatabaseIsSetUp: with the chart's persistence off,
// every restart came up on the seed with auth.enabled false -- setup had written
// it to a volume that no longer existed -- over a database holding the
// administrator. The refusal to start on a database that lost its
// administrator, and authentication on a management API served on a public
// entrypoint, both key on it.
func TestASeededStartOverASetUpDatabaseIsSetUp(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "shared.db")
	_, first, _ := bootSeeded(t, dbPath)
	if err := first.UpsertUser(&gateonv1.User{Username: "admin", Password: "correct-horse-battery", Role: auth.RoleAdmin}); err != nil {
		t.Fatal(err)
	}

	reg, m, path := bootSeeded(t, dbPath)
	AdoptSetUp(reg, m)
	if !reg.Get(t.Context()).GetAuth().GetEnabled() || !storedAuthEnabled(t, path) {
		t.Fatal("a seeded start over a database with an administrator is not marked set up")
	}
}

// TestASeededStartOverAnEmptyDatabaseIsAFirstRun: no administrator means setup
// has not run, and marking the gateway set up would make it refuse to start.
func TestASeededStartOverAnEmptyDatabaseIsAFirstRun(t *testing.T) {
	reg, m, path := bootSeeded(t, filepath.Join(t.TempDir(), "empty.db"))
	AdoptSetUp(reg, m)
	if reg.Get(t.Context()).GetAuth().GetEnabled() || storedAuthEnabled(t, path) {
		t.Fatal("a first run was marked set up")
	}
}
