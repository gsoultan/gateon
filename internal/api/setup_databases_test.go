// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// firstRun is a gateway before its first Setup: no global.json and no auth
// manager. Its data directory is a temporary one and, as packaged, so is its
// working directory -- a database that falls back to the default gateon.db
// lands there rather than in the checkout.
func firstRun(t *testing.T) (*ApiService, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dir)
	t.Chdir(dir)
	holder := auth.NewHolder(nil)
	t.Cleanup(func() { _ = holder.Close() })
	return &ApiService{Auth: holder, Globals: config.NewGlobalRegistry(filepath.Join(dir, "global.json"))}, dir
}

// TestSetupSavesTheDatabasesTheWizardChose.
//
// The dashboard calls Setup over Connect, and Setup never read database_url or
// database_config -- nor the logging database, which SetupRequest did not
// have. The only code that saved them was in the REST handler, which the
// dashboard does not call. So the wizard's database step was accepted and
// discarded: the operator chose a database, finished setup, and the gateway
// created the administrator in gateon.db and ran there.
func TestSetupSavesTheDatabasesTheWizardChose(t *testing.T) {
	svc, dir := firstRun(t)
	ctx := context.Background()
	chosen := filepath.Join(dir, "chosen.db")
	logs := filepath.Join(dir, "chosen-logs.db")
	secret := strings.Repeat("a", 32)

	resp, err := svc.Setup(ctx, &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "first-password", PasetoSecret: secret,
		DatabaseConfig:     &gateonv1.DatabaseConfig{Driver: "sqlite", SqlitePath: chosen},
		LoggingDatabaseUrl: logs,
	})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("Setup: err=%v resp=%v", err, resp)
	}

	conf := svc.Globals.Get(ctx)
	if got := db.AuthDatabaseURL(conf.GetAuth()); got != chosen {
		t.Errorf("auth database = %q, want the wizard's %q", got, chosen)
	}
	if got := db.AuditDatabaseURL(conf.GetAudit(), conf.GetAuth()); got != logs {
		t.Errorf("audit database = %q, want the wizard's %q", got, logs)
	}
	// Where the administrator was written: the database the next start opens.
	mgr, err := auth.NewManager(chosen, secret, logger.Default())
	if err != nil {
		t.Fatalf("open the chosen database: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	if _, _, err := mgr.Authenticate("admin", "first-password"); err != nil {
		t.Errorf("the administrator is not in the chosen database: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "gateon.db")); err == nil {
		t.Error("setup created the default gateon.db instead of using the database the wizard chose")
	}
}

// TestSetupWritesNoDatabaseOnceConfigured asks the takeover question of Setup
// itself, now that Setup is what saves the databases -- and Setup is public on
// Connect and gRPC as well as REST. On a configured gateway a caller-supplied
// database must be neither opened nor written, or anyone who can reach the
// management port could point the gateway's accounts at a server of their own
// for its next start.
func TestSetupWritesNoDatabaseOnceConfigured(t *testing.T) {
	svc, dir := firstRun(t)
	ctx := context.Background()
	if resp, err := svc.Setup(ctx, &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "first-password", PasetoSecret: strings.Repeat("a", 32),
	}); err != nil || !resp.GetSuccess() {
		t.Fatalf("first Setup: err=%v resp=%v", err, resp)
	}
	before, err := os.ReadFile(filepath.Join(dir, "global.json"))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := svc.Setup(ctx, &gateonv1.SetupRequest{
		AdminUsername: "attacker", AdminPassword: "attacker-password", PasetoSecret: strings.Repeat("z", 32),
		DatabaseUrl:        filepath.Join(dir, "attacker.db"),
		LoggingDatabaseUrl: filepath.Join(dir, "attacker-audit.db"),
	})
	if err != nil || resp.GetSuccess() {
		t.Fatalf("Setup on a configured gateway: err=%v resp=%v, want a refusal", err, resp)
	}
	after, err := os.ReadFile(filepath.Join(dir, "global.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("a refused Setup rewrote global.json:\n%s", after)
	}
	// Probing opens a database, and opening a SQLite one creates its file: its
	// absence is what shows the refusal came first.
	for _, name := range []string{"attacker.db", "attacker-audit.db"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s was opened by a Setup the gateway refused (stat err = %v)", name, err)
		}
	}
}

// TestSetupSavesNeitherDatabaseWhenOneCannotBeOpened: both databases are
// probed before either is written, and before the administrator is created, so
// a logging database that cannot be opened leaves nothing half applied -- not
// the management database in global.json, and not an account created in it.
func TestSetupSavesNeitherDatabaseWhenOneCannotBeOpened(t *testing.T) {
	svc, dir := firstRun(t)
	ctx := context.Background()

	resp, err := svc.Setup(ctx, &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "first-password", PasetoSecret: strings.Repeat("a", 32),
		DatabaseUrl: filepath.Join(dir, "chosen.db"),
		// Outside the data directory, where a database named over the network may not be.
		LoggingDatabaseUrl: filepath.Join(t.TempDir(), "logs.db"),
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if resp.GetSuccess() {
		t.Fatal("Setup succeeded with a logging database it may not open")
	}
	if !strings.Contains(resp.GetError(), "logging database") {
		t.Errorf("error %q does not say which database was refused", resp.GetError())
	}
	if _, err := os.Stat(filepath.Join(dir, "global.json")); !os.IsNotExist(err) {
		t.Errorf("a failed Setup wrote global.json (stat err = %v)", err)
	}
	if auth.Available(svc.Auth) {
		t.Error("a failed Setup installed an auth manager")
	}
}
