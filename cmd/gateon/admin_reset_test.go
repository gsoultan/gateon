// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var (
	auditDBOnce sync.Once
	auditDBPath string
)

// sharedAuditDB is one audit database for the whole test binary: the audit
// log is process-global and opened once, by whichever test resets first.
func sharedAuditDB(t *testing.T) string {
	t.Helper()
	auditDBOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gateon-admin-reset-audit-*")
		if err != nil {
			t.Fatal(err)
		}
		auditDBPath = filepath.Join(dir, "audit.db")
	})
	return auditDBPath
}

func asEUID(t *testing.T, euid int) {
	t.Helper()
	prev := currentEUID
	currentEUID = func() int { return euid }
	t.Cleanup(func() { currentEUID = prev })
}

// A gateway whose every administrator is in an attacker's hands, on disk: its
// configuration and its user database, with the owner's account demoted.
func lockedOutGateway(t *testing.T) (dir, dbPath string) {
	t.Helper()
	dir = t.TempDir()
	dbPath = filepath.Join(dir, "gateon.db")
	const secret = "0123456789abcdef0123456789abcdef"
	gc := map[string]any{
		"auth":  map[string]any{"enabled": true, "sqlite_path": dbPath, "paseto_secret": secret},
		"audit": map[string]any{"enabled": true, "database_url": "sqlite:" + sharedAuditDB(t)},
	}
	b, _ := json.Marshal(gc)
	if err := os.WriteFile(filepath.Join(dir, "global.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := auth.NewManager(dbPath, secret, logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.UpsertUser(&gateonv1.User{Username: "rightful", Password: "attacker-set-secret-1", Role: auth.RoleViewer}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GLOBAL_CONFIG_FILE", filepath.Join(dir, "global.json"))
	t.Setenv("GATEON_DATA_DIR", dir)
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	return dir, dbPath
}

// Before this command a locked-out owner had no way back: the dashboard was
// the attacker's, and a database emptied of administrators refuses to start.
func TestAdminResetGivesTheAccountBack(t *testing.T) {
	asEUID(t, 0)
	_, dbPath := lockedOutGateway(t)
	var recorded []audit.AuditEntry
	defer audit.AddSink(func(e audit.AuditEntry) {
		if e.Action == "admin_reset" {
			recorded = append(recorded, e)
		}
	})()
	var out, errOut bytes.Buffer
	code := adminCLI([]string{"reset", "rightful", "--env-file", os.DevNull}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	pw := regexp.MustCompile(`Password: (\S+)`).FindStringSubmatch(out.String())
	if pw == nil {
		t.Fatalf("no password printed: %q", out.String())
	}
	m, err := auth.NewManager(dbPath, "0123456789abcdef0123456789abcdef", logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, _, err := m.Authenticate("rightful", pw[1], "192.0.2.1:1"); err != auth.ErrTwoFactorSetupRequired &&
		!strings.Contains(errString(err), "setup required") {
		t.Fatalf("signing in with the printed password: %v, want the second-factor enrolment it owes", err)
	}
	if len(recorded) != 1 || !strings.Contains(recorded[0].Details, "rightful") {
		t.Fatalf("audit entries for the reset = %+v, want one naming the account", recorded)
	}
	users, _, err := m.ListUsers(0, 10, "rightful")
	if err != nil || len(users) != 1 || users[0].Role != auth.RoleAdmin || users[0].Disabled {
		t.Fatalf("account after reset = %+v, %v; want an enabled administrator", users, err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestAdminResetRefusesAnyoneButRoot(t *testing.T) {
	asEUID(t, 1000)
	lockedOutGateway(t)
	var out, errOut bytes.Buffer
	if code := adminCLI([]string{"reset", "rightful"}, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "root") {
		t.Fatalf("exit %d, stderr %q: want a refusal naming root", code, errOut.String())
	}
	if strings.Contains(out.String(), "Password") {
		t.Fatal("a password was printed to a caller who is not root")
	}
}

func TestAdminResetRefusesAMissingAccountWithoutCreate(t *testing.T) {
	asEUID(t, 0)
	lockedOutGateway(t)
	var out, errOut bytes.Buffer
	if code := adminCLI([]string{"reset", "nobody", "--env-file", os.DevNull}, &out, &errOut); code == 0 {
		t.Fatal("reset an account that does not exist without --create")
	}
	if code := adminCLI([]string{"reset", "--create", "--env-file", os.DevNull, "rescuer"}, &out, &errOut); code != 0 {
		t.Fatalf("--create: exit %d: %s", code, errOut.String())
	}
}

func TestParseResetArgs(t *testing.T) {
	for _, args := range [][]string{{}, {"--create"}, {"--bogus", "x"}} {
		if _, err := parseResetArgs(args); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
	o, err := parseResetArgs([]string{"alice", "--create", "--env-file", "/x"})
	if err != nil || o.username != "alice" || !o.create || o.envFile != "/x" {
		t.Fatalf("got %+v, %v", o, err)
	}
}

func TestEnvFileFillsOnlyWhatIsUnset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	content := "# comment\nGATEON_T_A=from-file\nexport GATEON_T_B=\"quoted value\"\nGATEON_T_C='single'\nnot a line\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GATEON_T_A", "already")
	t.Setenv("GATEON_T_B", "")
	os.Unsetenv("GATEON_T_B")
	t.Setenv("GATEON_T_C", "")
	os.Unsetenv("GATEON_T_C")
	if err := loadEnvFile(path, true); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("GATEON_T_A") != "already" || os.Getenv("GATEON_T_B") != "quoted value" || os.Getenv("GATEON_T_C") != "single" {
		t.Fatalf("A=%q B=%q C=%q", os.Getenv("GATEON_T_A"), os.Getenv("GATEON_T_B"), os.Getenv("GATEON_T_C"))
	}
	if err := loadEnvFile(filepath.Join(t.TempDir(), "missing"), true); err == nil {
		t.Fatal("a named env file that is missing was ignored")
	}
}
