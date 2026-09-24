// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const initRegistriesChildEnv = "GATEON_TEST_RUN_INIT_CONFIG_REGISTRIES"

// TestStartupRefusesAGlobalConfigItCannotParse runs initConfigRegistries in a
// child process against a global.json with one mistake in it, because refusing
// means exiting and exiting would take the test binary with it.
//
// Startup used to log the parse error and carry on with the built-in defaults:
// the WAF off, the management plane on every interface for every address, and
// no auth database, so the bootstrap pointed auth at a fresh local SQLite file.
// On a Postgres-backed install that file has no administrator, which reopens the
// first-run Setup endpoint to whoever reaches the port first. A gateway that
// does not start is noticed in minutes; that one looked healthy.
func TestStartupRefusesAGlobalConfigItCannotParse(t *testing.T) {
	if os.Getenv(initRegistriesChildEnv) == "1" {
		initConfigRegistries()
		os.Exit(0) // reached only when startup accepted the file
	}

	path := filepath.Join(t.TempDir(), "global.json")
	malformed := `{"waf": {"enabled": true}, "management": {"port": 9443, "allowed_ips": ["10.0.0.0/8"]}}`
	if err := os.WriteFile(path, []byte(malformed), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runInitRegistriesChild(t, path)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
		t.Fatalf("startup went on with a global.json it could not parse (err=%v); output:\n%s", err, out)
	}
}

// TestStartupAcceptsAGoodOrAbsentGlobalConfig keeps the refusal from being
// satisfied by a child that fails for any reason at all: the same child, given
// a good file and then none (the first run), must start.
func TestStartupAcceptsAGoodOrAbsentGlobalConfig(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "global.json")
	if err := os.WriteFile(good, []byte(`{"waf": {"enabled": true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"good": good, "absent": filepath.Join(dir, "absent.json")} {
		if out, err := runInitRegistriesChild(t, path); err != nil {
			t.Errorf("%s global.json: startup refused (%v); output:\n%s", name, err, out)
		}
	}
}

func runInitRegistriesChild(t *testing.T, globalFile string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestStartupRefusesAGlobalConfigItCannotParse$") // #nosec G204 -- the test binary re-running itself
	cmd.Env = append(os.Environ(), initRegistriesChildEnv+"=1", "GLOBAL_CONFIG_FILE="+globalFile)
	cmd.Dir = t.TempDir()
	return cmd.CombinedOutput()
}
