// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"
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

// configuredGlobal is a global.json that names its user database, as the Helm
// chart renders one from externalDatabase: SQLite here, so the test needs no
// server; the rule does not look at the engine.
const configuredGlobal = `{"auth": {"database_config": {"driver": "sqlite", "sqlite_path": "configured.db"}}}`

// configuredGateway is a gateway that started on a global.json naming its
// database and has no administrator yet: what bootstrap.InitGlobalConfig
// leaves -- the auth service up, on the configured database -- before setup.
func configuredGateway(t *testing.T, global string) (*ApiService, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dir)
	t.Chdir(dir)
	path := filepath.Join(dir, "global.json")
	if err := os.WriteFile(path, []byte(global), 0o600); err != nil {
		t.Fatal(err)
	}
	globals := config.NewGlobalRegistry(path)
	mgr, err := auth.NewManager(db.AuthDatabaseURL(globals.Get(context.Background()).GetAuth()),
		strings.Repeat("k", 32), logger.Default())
	if err != nil {
		t.Fatalf("open the configured database: %v", err)
	}
	holder := auth.NewHolder(mgr)
	t.Cleanup(func() { _ = holder.Close() })
	return &ApiService{Auth: holder, Globals: globals, SetupToken: newTestSetupToken(t)}, dir
}

// restartedAdministrator is what the next start finds: the user database the
// stored global.json names, opened fresh, and whether the administrator signs
// in there. bootstrap refuses to start when it does not.
func restartedAdministrator(t *testing.T, dir, user, password string) error {
	t.Helper()
	stored := config.NewGlobalRegistry(filepath.Join(dir, "global.json")).Get(context.Background())
	mgr, err := auth.NewManager(db.AuthDatabaseURL(stored.GetAuth()), strings.Repeat("k", 32), logger.Default())
	if err != nil {
		t.Fatalf("open the database global.json names: %v", err)
	}
	defer func() { _ = mgr.Close() }()
	_, _, err = mgr.Authenticate(user, password, "")
	return err
}

// TestSetupKeepsTheDatabaseAConfiguredGatewayHasOpen is the crash loop.
//
// The wizard always submits a database, SQLite gateon.db by default. On a
// gateway whose configuration already named one, Setup created the
// administrator in the database that was open and then wrote the wizard's
// over the configuration -- so the next start opened gateon.db, found no
// administrator, and refused to run ("the user database has no
// administrator"), every restart. Setup now refuses a different database, and
// completes on the configured one.
func TestSetupKeepsTheDatabaseAConfiguredGatewayHasOpen(t *testing.T) {
	svc, dir := configuredGateway(t, configuredGlobal)
	ctx := context.Background()
	req := &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "first-password", PasetoSecret: strings.Repeat("a", 32),
		SetupToken:     svc.SetupToken.Value(),
		DatabaseConfig: &gateonv1.DatabaseConfig{Driver: "sqlite", SqlitePath: "gateon.db"},
	}

	resp, err := svc.Setup(ctx, req)
	if err != nil || resp.GetSuccess() || !strings.Contains(resp.GetError(), errDatabaseConfigured.Error()) {
		t.Fatalf("Setup naming another database on a configured gateway: err=%v resp=%v; want refused with %q",
			err, resp, errDatabaseConfigured)
	}
	if !strings.Contains(resp.GetError(), "configured.db") {
		t.Errorf("the refusal does not say which database is kept: %q", resp.GetError())
	}
	if _, err := os.Stat(filepath.Join(dir, "gateon.db")); !os.IsNotExist(err) {
		t.Errorf("a refused Setup opened the wizard's database (stat err = %v)", err)
	}
	if svc.Auth.IsSetupDone() {
		t.Fatal("a refused Setup created the administrator")
	}

	req.DatabaseConfig = nil
	if resp, err := svc.Setup(ctx, req); err != nil || !resp.GetSuccess() {
		t.Fatalf("Setup with no database on a configured gateway: err=%v resp=%v", err, resp)
	}
	if err := restartedAdministrator(t, dir, "admin", "first-password"); err != nil {
		t.Fatalf("after setup, the database global.json names has no administrator who signs in: %v", err)
	}
}

// TestSetupAcceptsTheConfiguredDatabaseUnderAnotherSpelling: a request that
// names the database already open -- the wizard's form of what global.json
// holds -- is the same choice, and is not refused.
func TestSetupAcceptsTheConfiguredDatabaseUnderAnotherSpelling(t *testing.T) {
	svc, dir := configuredGateway(t, configuredGlobal)
	resp, err := svc.Setup(context.Background(), &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "first-password", PasetoSecret: strings.Repeat("a", 32),
		SetupToken:  svc.SetupToken.Value(),
		DatabaseUrl: "sqlite:configured.db",
	})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("Setup naming the configured database: err=%v resp=%v", err, resp)
	}
	if err := restartedAdministrator(t, dir, "admin", "first-password"); err != nil {
		t.Fatalf("after setup the administrator does not sign in on the next start: %v", err)
	}
}

// TestSetupRefusesAnotherLoggingDatabaseOnAConfiguredGateway: the audit log
// opened at start from the same configuration; a logging database chosen in
// setup would have split it between two databases across a restart.
func TestSetupRefusesAnotherLoggingDatabaseOnAConfiguredGateway(t *testing.T) {
	svc, dir := configuredGateway(t, configuredGlobal)
	resp, err := svc.Setup(context.Background(), &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "first-password", PasetoSecret: strings.Repeat("a", 32),
		SetupToken:         svc.SetupToken.Value(),
		LoggingDatabaseUrl: "logs.db",
	})
	if err != nil || resp.GetSuccess() || !strings.Contains(resp.GetError(), "logging database") {
		t.Fatalf("Setup naming another logging database: err=%v resp=%v; want refused naming the logging database", err, resp)
	}
	if _, err := os.Stat(filepath.Join(dir, "logs.db")); !os.IsNotExist(err) {
		t.Errorf("a refused Setup opened the wizard's logging database (stat err = %v)", err)
	}
}

// TestIsSetupRequiredSaysWhichDatabaseSetupKeeps: the wizard has to know the
// step is decided before it offers it, and the address only to the operator.
func TestIsSetupRequiredSaysWhichDatabaseSetupKeeps(t *testing.T) {
	svc, dir := configuredGateway(t, configuredGlobal)
	ctx := context.Background()

	public, err := svc.IsSetupRequired(ctx, &gateonv1.IsSetupRequiredRequest{})
	if err != nil || !public.GetRequired() || !public.GetDatabaseConfigured() || public.GetDatabaseDriver() != db.DriverSQLite {
		t.Fatalf("IsSetupRequired on a configured gateway = %v (err %v); want required, configured, sqlite", public, err)
	}
	if public.GetDatabaseDescription() != "" {
		t.Errorf("the database's location went to a caller without the setup token: %q", public.GetDatabaseDescription())
	}
	wrong, _ := svc.IsSetupRequired(ctx, &gateonv1.IsSetupRequiredRequest{SetupToken: "not-the-token"})
	if wrong.GetDatabaseDescription() != "" {
		t.Errorf("a wrong setup token was given the database's location: %q", wrong.GetDatabaseDescription())
	}
	operator, _ := svc.IsSetupRequired(ctx, &gateonv1.IsSetupRequiredRequest{SetupToken: svc.SetupToken.Value()})
	if want := filepath.Join(dir, "configured.db"); operator.GetDatabaseDescription() != want {
		t.Errorf("database_description = %q, want %q", operator.GetDatabaseDescription(), want)
	}
	if operator.GetLoggingDatabaseDescription() != "" {
		t.Errorf("logging_database_description = %q for logs kept in the management database", operator.GetLoggingDatabaseDescription())
	}

	fresh, _ := firstRun(t)
	if got, _ := fresh.IsSetupRequired(ctx, &gateonv1.IsSetupRequiredRequest{}); got.GetDatabaseConfigured() {
		t.Error("a first run with no global.json says a database is configured; the wizard would hide its database step")
	}
}

// TestIsSetupRequiredSaysTheSessionKeyComesFromTheEnvironment: with the key
// named by reference (GATEON_SESSION_KEY, ADR 0056), Setup keeps it and
// ignores the wizard's, so the wizard must not present a generated key as the
// one in use.
func TestIsSetupRequiredSaysTheSessionKeyComesFromTheEnvironment(t *testing.T) {
	t.Setenv(config.SessionKeyEnv, "")
	plain, _ := configuredGateway(t, configuredGlobal)
	if got, _ := plain.IsSetupRequired(context.Background(), &gateonv1.IsSetupRequiredRequest{}); got.GetSessionKeyFromEnvironment() {
		t.Error("session_key_from_environment with no key from the environment")
	}

	t.Setenv(config.SessionKeyEnv, strings.Repeat("e", 32))
	svc, _ := configuredGateway(t, `{"auth": {"paseto_secret": "$env:`+config.SessionKeyEnv+`"}}`)
	got, err := svc.IsSetupRequired(context.Background(), &gateonv1.IsSetupRequiredRequest{})
	if err != nil || !got.GetSessionKeyFromEnvironment() {
		t.Fatalf("IsSetupRequired with the key from %s = %v (err %v); want session_key_from_environment",
			config.SessionKeyEnv, got, err)
	}
}

// TestIsSetupRequiredSaysNothingOnceSetUp: the answer is public for the life
// of the process, and once setup is done there is nothing for a wizard to do.
func TestIsSetupRequiredSaysNothingOnceSetUp(t *testing.T) {
	svc, _ := configuredGateway(t, configuredGlobal)
	ctx := context.Background()
	token := svc.SetupToken.Value()
	if resp, err := svc.Setup(ctx, &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "first-password", PasetoSecret: strings.Repeat("a", 32), SetupToken: token,
	}); err != nil || !resp.GetSuccess() {
		t.Fatalf("Setup: err=%v resp=%v", err, resp)
	}
	got, err := svc.IsSetupRequired(ctx, &gateonv1.IsSetupRequiredRequest{SetupToken: token})
	if err != nil || got.GetRequired() || got.GetDatabaseConfigured() || got.GetDatabaseDriver() != "" {
		t.Errorf("IsSetupRequired after setup = %v (err %v); want nothing but required=false", got, err)
	}
}

// TestRefuseDatabaseIsErrDatabaseConfigured keeps the refusal matchable.
func TestRefuseDatabaseIsErrDatabaseConfigured(t *testing.T) {
	if err := refuseDatabase("", "postgres://u:secret@db.internal:5432/gateon"); !errors.Is(err, errDatabaseConfigured) ||
		strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "db.internal:5432/gateon") {
		t.Errorf("refuseDatabase = %v; want errDatabaseConfigured naming the server without its credentials", err)
	}
}
