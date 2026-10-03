// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package inits

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// bootHelperEnv makes this test binary run InitGlobalConfig on the global.json
// it names and exit, so a test can watch a refusal that ends the process.
const bootHelperEnv = "GATEON_TEST_BOOT_GLOBAL_FILE"

func TestMain(m *testing.M) {
	if file := os.Getenv(bootHelperEnv); file != "" {
		mgr := InitGlobalConfig(file, config.NewGlobalRegistry(file))
		if mgr != nil {
			_ = mgr.Close()
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// writeGlobal writes a global.json holding auth, the way setup leaves it.
func writeGlobal(t *testing.T, dir string, a *gateonv1.AuthConfig) string {
	t.Helper()
	b, err := protojson.Marshal(&gateonv1.GlobalConfig{Auth: a})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "global.json")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// boot runs InitGlobalConfig in a child process with dir as its data directory
// and working directory, and returns its exit error and log.
func boot(t *testing.T, dir, globalFile string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$") // #nosec G204 -- this test binary
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), bootHelperEnv+"="+globalFile, "GATEON_DATA_DIR="+dir)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

const setUpKey = "0123456789abcdef0123456789abcdef"

// TestBootRefusesASetUpGatewayWhoseDatabaseIsGone: a gateway set up on SQLite
// whose database file is no longer there -- a data directory that did not
// mount, a restore that missed the file -- used to open it, which created it
// empty, and with no administrator in it first-run setup reopened to whoever
// reached the management port first. It must refuse to start, and leave no
// empty database behind for the next start to accept.
func TestBootRefusesASetUpGatewayWhoseDatabaseIsGone(t *testing.T) {
	dir := t.TempDir()
	file := writeGlobal(t, dir, &gateonv1.AuthConfig{Enabled: true, PasetoSecret: setUpKey, SqlitePath: "gateon.db"})

	log, err := boot(t, dir, file)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() == 0 {
		t.Fatalf("a set-up gateway whose user database is missing started (err=%v); log:\n%s", err, log)
	}
	if !strings.Contains(log, "does not exist") {
		t.Errorf("the refusal does not say the database is missing; log:\n%s", log)
	}
	if _, err := os.Stat(filepath.Join(dir, "gateon.db")); err == nil {
		t.Error("the refusal created an empty gateon.db, which the next start would accept")
	}
}

// TestBootRefusesASetUpGatewayWithAnEmptyDatabase: the same reopening by the
// other road -- the database is there and holds no administrator.
func TestBootRefusesASetUpGatewayWithAnEmptyDatabase(t *testing.T) {
	dir := t.TempDir()
	m, err := auth.NewManager(filepath.Join(dir, "gateon.db"), setUpKey, logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	_ = m.Close()
	file := writeGlobal(t, dir, &gateonv1.AuthConfig{Enabled: true, PasetoSecret: setUpKey, SqlitePath: "gateon.db"})

	log, err := boot(t, dir, file)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() == 0 {
		t.Fatalf("a set-up gateway with an empty user database started (err=%v); log:\n%s", err, log)
	}
	if !strings.Contains(log, "no administrator") {
		t.Errorf("the refusal does not say there is no administrator; log:\n%s", log)
	}
}

// TestBootStartsASetUpGatewayWithItsAdministrator is the control: the same
// global.json over a database that has its administrator starts.
func TestBootStartsASetUpGatewayWithItsAdministrator(t *testing.T) {
	dir := t.TempDir()
	m, err := auth.NewManager(filepath.Join(dir, "gateon.db"), setUpKey, logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertUser(&gateonv1.User{Username: "admin", Password: "correct-horse-battery", Role: auth.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	_ = m.Close()
	file := writeGlobal(t, dir, &gateonv1.AuthConfig{Enabled: true, PasetoSecret: setUpKey, SqlitePath: "gateon.db"})

	if log, err := boot(t, dir, file); err != nil {
		t.Fatalf("a set-up gateway with its administrator did not start: %v; log:\n%s", err, log)
	}
}

// TestBootOpensTheDatabaseInTheDataDirectory: a relative SQLite path was opened
// against the working directory, so a gateway started anywhere but its data
// directory found no database there, created one, and reopened setup.
func TestBootOpensTheDatabaseInTheDataDirectory(t *testing.T) {
	dataDir, elsewhere := t.TempDir(), t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dataDir)
	file := writeGlobal(t, dataDir, &gateonv1.AuthConfig{PasetoSecret: setUpKey, SqlitePath: "gateon.db"})
	t.Chdir(elsewhere)

	mgr := InitGlobalConfig(file, config.NewGlobalRegistry(file))
	if mgr == nil {
		t.Fatal("no auth manager")
	}
	t.Cleanup(func() { _ = mgr.Close() })
	if _, err := os.Stat(filepath.Join(dataDir, "gateon.db")); err != nil {
		t.Errorf("the user database is not in the data directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "gateon.db")); err == nil {
		t.Error("the user database was created in the working directory")
	}
}
