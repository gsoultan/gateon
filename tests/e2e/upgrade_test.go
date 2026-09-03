// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// redis.enabled and otel.enabled now gate subsystems that previously ran on the
// strength of an address alone. Everything about that change is covered by unit
// tests, but nobody had taken a config written *before* it and started the real
// binary on one -- which is the only thing an operator upgrading will actually
// do.
//
// The warning is the whole mitigation. proto3 cannot distinguish an unset bool
// from an explicit false, so no migration can tell "never set it" from "turned
// it off"; a line at startup is what stands between an operator and a silently
// cold cache.
//
// Opt-in with the other e2e tests: this builds and runs the real binary.

// writePreUpgradeGlobalConfig rewrites the copied global.json into the shape a
// config predating the change has: an address and an endpoint, no flags.
func writePreUpgradeGlobalConfig(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read global.json: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse global.json: %v", err)
	}

	// Exactly what a working pre-change deployment looks like. No "enabled" key
	// on either, which is the case that used to connect and now does not.
	cfg["redis"] = map[string]any{"addr": "127.0.0.1:6379"}
	cfg["otel"] = map[string]any{"endpoint": "127.0.0.1:4318"}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal global.json: %v", err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write global.json: %v", err)
	}
}

func TestUpgradeWarnsAboutConfigThatUsedToWork(t *testing.T) {
	if os.Getenv("GATEON_SOAK_TEST") != "1" {
		t.Skip("builds and runs the binary: set GATEON_SOAK_TEST=1")
	}
	projectRoot, _ := filepath.Abs("../..")
	env := SetupTestEnv(t)
	writePreUpgradeGlobalConfig(t, filepath.Join(env.Dir, "config/global.json"))

	binary := filepath.Join(env.Dir, "gateon"+exeSuffix())
	build := exec.Command("go", "build", "-o", binary, "./cmd/gateon")
	build.Dir = projectRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gateon: %v\n%s", err, out)
	}

	cmd := exec.Command(binary)
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(),
		"GLOBAL_CONFIG_FILE="+filepath.Join(env.Dir, "config/global.json"),
		"ROUTES_FILE="+filepath.Join(env.Dir, "config/routes.json"),
		"SERVICES_FILE="+filepath.Join(env.Dir, "config/services.json"),
		"ENTRYPOINTS_FILE="+filepath.Join(env.Dir, "config/entrypoints.json"),
		"MIDDLEWARES_FILE="+filepath.Join(env.Dir, "config/middlewares.json"),
		"TLS_OPTIONS_FILE="+filepath.Join(env.Dir, "config/tls_options.json"),
		"GATEON_TEST=1",
	)

	// The warning goes to the log, so the log is what has to be inspected. An
	// operator reads exactly this.
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Start(); err != nil {
		t.Fatalf("start gateon: %v", err)
	}
	waitForPort(t, env.Ports["http_tls"])
	// Give startup logging a moment to flush before reading.
	time.Sleep(500 * time.Millisecond)

	_ = cmd.Process.Signal(os.Interrupt)
	_ = cmd.Wait()

	logs := out.String()

	for _, want := range []string{"redis.enabled", "otel.enabled"} {
		if !strings.Contains(logs, want) {
			t.Errorf("startup log never mentions %q; an operator upgrading gets no warning "+
				"that a subsystem stopped connecting", want)
		}
	}
	// The warning has to say what to do, not merely that something is off.
	if !strings.Contains(logs, "will NOT be used") && !strings.Contains(logs, "will NOT be exported") {
		t.Error("the warning does not state the consequence")
	}
	if t.Failed() {
		t.Logf("startup log follows:\n%s", logs)
	}
}

// The mirror: a config that sets the flags must start silently. A warning that
// fires for correct configuration is one operators learn to ignore.
func TestUpgradeIsSilentForAConfigThatSetsTheFlags(t *testing.T) {
	if os.Getenv("GATEON_SOAK_TEST") != "1" {
		t.Skip("builds and runs the binary: set GATEON_SOAK_TEST=1")
	}
	projectRoot, _ := filepath.Abs("../..")
	env := SetupTestEnv(t)

	path := filepath.Join(env.Dir, "config/global.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read global.json: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse global.json: %v", err)
	}
	cfg["redis"] = map[string]any{"enabled": true, "addr": "127.0.0.1:6379"}
	cfg["otel"] = map[string]any{"enabled": true, "endpoint": "127.0.0.1:4318"}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write global.json: %v", err)
	}

	binary := filepath.Join(env.Dir, "gateon"+exeSuffix())
	build := exec.Command("go", "build", "-o", binary, "./cmd/gateon")
	build.Dir = projectRoot
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gateon: %v\n%s", err, b)
	}

	cmd := exec.Command(binary)
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(),
		"GLOBAL_CONFIG_FILE="+path,
		"ROUTES_FILE="+filepath.Join(env.Dir, "config/routes.json"),
		"SERVICES_FILE="+filepath.Join(env.Dir, "config/services.json"),
		"ENTRYPOINTS_FILE="+filepath.Join(env.Dir, "config/entrypoints.json"),
		"MIDDLEWARES_FILE="+filepath.Join(env.Dir, "config/middlewares.json"),
		"TLS_OPTIONS_FILE="+filepath.Join(env.Dir, "config/tls_options.json"),
		"GATEON_TEST=1",
	)
	var out2 strings.Builder
	cmd.Stdout = &out2
	cmd.Stderr = &out2

	if err := cmd.Start(); err != nil {
		t.Fatalf("start gateon: %v", err)
	}
	waitForPort(t, env.Ports["http_tls"])
	time.Sleep(500 * time.Millisecond)
	_ = cmd.Process.Signal(os.Interrupt)
	_ = cmd.Wait()

	if strings.Contains(out2.String(), "will NOT be used") {
		t.Error("a correctly configured deployment got the upgrade warning; " +
			"a warning that fires when nothing is wrong is one nobody reads")
	}
}
