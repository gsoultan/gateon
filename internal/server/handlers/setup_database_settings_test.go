// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// setupGlobalsAPI is the slice of the API the POST /v1/setup handler touches:
// the setup state, the global config store, and Setup itself, which answers
// the way the real one does on a configured gateway and records what it was
// handed.
type setupGlobalsAPI struct {
	GlobalAndAuthAPI
	required bool
	globals  config.GlobalConfigStore
	got      *gateonv1.SetupRequest
}

func (s *setupGlobalsAPI) GetGlobals() config.GlobalConfigStore { return s.globals }

func (s *setupGlobalsAPI) IsSetupRequired(_ context.Context, _ *gateonv1.IsSetupRequiredRequest) (*gateonv1.IsSetupRequiredResponse, error) {
	return &gateonv1.IsSetupRequiredResponse{Required: s.required}, nil
}

func (s *setupGlobalsAPI) Setup(_ context.Context, req *gateonv1.SetupRequest) (*gateonv1.SetupResponse, error) {
	s.got = req
	if !s.required {
		return &gateonv1.SetupResponse{Success: false, Error: "setup already completed"}, nil
	}
	return &gateonv1.SetupResponse{Success: true}, nil
}

func postSetup(t *testing.T, svc GlobalAndAuthAPI, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, svc, &Deps{})
	req := httptest.NewRequest(http.MethodPost, "/v1/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// attackerDatabaseBody names a management and an audit database of the
// caller's choosing, both SQLite files so validateDatabase can open them
// without a server.
func attackerDatabaseBody(dir string) string {
	b, _ := json.Marshal(map[string]string{
		"admin_username":       "attacker",
		"admin_password":       "attacker-password",
		"paseto_secret":        strings.Repeat("z", 32),
		"database_url":         "sqlite:" + filepath.Join(dir, "attacker.db"),
		"logging_database_url": "sqlite:" + filepath.Join(dir, "attacker-audit.db"),
	})
	return string(b)
}

// TestSetupDoesNotRewriteTheDatabaseOfAConfiguredGateway is the takeover.
//
// POST /v1/setup is served without authentication for as long as the gateway
// runs, because it has to be reachable before an administrator exists. The
// handler persisted any database_url / database_config in the body to
// global.json first and only then called Setup -- which refused, and the
// response said "setup already completed". The refusal came after the write.
// So anyone who could reach the management port could point a configured
// gateway's management and audit databases at their own, and at the next
// restart the gateway loaded that database: the operator's accounts gone,
// setup open again, the attacker's routes and middlewares in force. Reproduced
// against the real binary before this test was written.
func TestSetupDoesNotRewriteTheDatabaseOfAConfiguredGateway(t *testing.T) {
	dir := t.TempDir()
	// Inside the data directory, so db.ConfineSQLite cannot be what refuses.
	t.Setenv("GATEON_DATA_DIR", dir)
	path := filepath.Join(dir, "global.json")
	original := []byte(`{"auth": {"enabled": true, "sqlite_path": "gateon.db"}}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	globals := config.NewGlobalRegistry(path)

	rr := postSetup(t, &setupGlobalsAPI{required: false, globals: globals}, attackerDatabaseBody(dir))

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 once setup is complete", rr.Code)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(onDisk), "attacker") {
		t.Fatalf("an unauthenticated setup call rewrote global.json on a configured gateway:\n%s", onDisk)
	}
	if got := globals.Get(context.Background()).GetAuth().GetDatabaseUrl(); got != "" {
		t.Errorf("live auth.database_url = %q, want it untouched", got)
	}
	// validateDatabase opens the DSN it is given, which for SQLite creates the
	// file: the handler must refuse before reaching a caller-supplied database.
	for _, name := range []string{"attacker.db", "attacker-audit.db"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s was opened after setup completed (stat err = %v)", name, err)
		}
	}
}

// TestSetupHandsTheWizardsDatabasesToSetup keeps the guard from being too
// tight: on a first run the wizard's databases must reach Setup, which
// validates and saves them for every transport.
//
// The handler used to save them itself, reading them through encoding/json
// tags in snake_case, and handed Setup the admin fields alone. The dashboard
// writes protojson's lowerCamel -- "databaseConfig", "sqlitePath",
// "loggingDatabaseUrl" -- which those tags do not match even
// case-insensitively, so its body saved nothing. Both spellings must arrive.
func TestSetupHandsTheWizardsDatabasesToSetup(t *testing.T) {
	// A handler that opens or saves a database itself -- as this one did --
	// must do it here and not in the checkout, and must find a store to save
	// into rather than stopping on a nil one: this test has to fail cleanly
	// against the code it replaced, not only pass against the fix.
	dir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dir)
	t.Chdir(dir)
	secret := strings.Repeat("s", 32)
	// Loopback port 1: refused at once, so a handler that dials it fails fast
	// without reaching past this host.
	for name, body := range map[string]string{
		"dashboard": `{"adminUsername":"admin","pasetoSecret":"` + secret + `","setupToken":"tok-1234567890abcdef",` +
			`"databaseConfig":{"driver":"sqlite","sqlitePath":"chosen.db"},` +
			`"loggingDatabaseConfig":{"driver":"postgres","host":"127.0.0.1","port":1,"sslMode":"require"}}`,
		"proto names": `{"admin_username":"admin","paseto_secret":"` + secret + `","setup_token":"tok-1234567890abcdef",` +
			`"database_config":{"driver":"sqlite","sqlite_path":"chosen.db"},` +
			`"logging_database_config":{"driver":"postgres","host":"127.0.0.1","port":1,"ssl_mode":"require"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			svc := &setupGlobalsAPI{required: true, globals: config.NewGlobalRegistry(filepath.Join(dir, name+".json"))}
			rr := postSetup(t, svc, body)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 during first-run setup: %s", rr.Code, rr.Body)
			}
			if svc.got == nil {
				t.Fatal("the handler never called Setup")
			}
			if got := svc.got.GetDatabaseConfig().GetSqlitePath(); got != "chosen.db" {
				t.Errorf("Setup got database_config.sqlite_path %q, want %q", got, "chosen.db")
			}
			logs := svc.got.GetLoggingDatabaseConfig()
			if logs.GetHost() != "127.0.0.1" || logs.GetPort() != 1 || logs.GetSslMode() != "require" {
				t.Errorf("Setup got logging_database_config %v, want the wizard's host, port and ssl mode", logs)
			}
			if got := svc.got.GetPasetoSecret(); got != secret {
				t.Errorf("Setup got paseto_secret %q, want the one sent", got)
			}
			// Setup checks the setup token; a handler that dropped it would refuse
			// every REST setup.
			if got := svc.got.GetSetupToken(); got != "tok-1234567890abcdef" {
				t.Errorf("Setup got setup_token %q, want the one sent", got)
			}
		})
	}
}
