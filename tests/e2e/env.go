// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type TestEnv struct {
	Dir        string
	BinaryPath string
	Ports      map[string]int
}

func SetupTestEnv(t *testing.T) *TestEnv {
	projectRoot, _ := filepath.Abs("../..")

	// t.TempDir(), not the repository root. Building test binaries into the
	// checkout left gateon_<TestName> and mock_backend_<TestName> artifacts
	// lying around after every run, and a subtest name contains a '/', which
	// turns the -o argument into a path through a directory that does not
	// exist — the build then fails and the test dies later at exec with a
	// confusing "no such file or directory". t.TempDir is also removed for us,
	// including when the test fails.
	tmpDir := t.TempDir()

	binaryPath := filepath.Join(tmpDir, "gateon"+exeSuffix())

	t.Logf("Building gateon binary into %s...", tmpDir)
	// We use 'go' directly here as it's a child process, but we ensure it's a fresh build.
	cmdBuild := exec.Command("go", "build", "-o", binaryPath, "./cmd/gateon")
	cmdBuild.Dir = projectRoot
	if out, err := cmdBuild.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build gateon: %v\n%s", err, out)
	}
	if _, err := os.Stat(binaryPath); err != nil {
		// Fail here, where the cause is obvious, rather than at exec time.
		t.Fatalf("build reported success but %s is missing: %v", binaryPath, err)
	}

	env := &TestEnv{
		Dir:        tmpDir,
		BinaryPath: binaryPath,
		Ports:      make(map[string]int),
	}

	// Allocate unique ports
	env.Ports["mgmt"] = getFreePort(t)
	env.Ports["http_plain"] = getFreePort(t)
	env.Ports["http_tls"] = getFreePort(t)
	env.Ports["grpc"] = getFreePort(t)
	env.Ports["tcp"] = getFreePort(t)
	env.Ports["mock_backend"] = getFreePort(t)

	// Create config dir
	configDir := filepath.Join(tmpDir, "config")
	_ = os.MkdirAll(configDir, 0o750)

	// Generate certificates in temp dir
	t.Log("Generating TLS certificates...")
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	// Use SAN for both localhost and 127.0.0.1
	cmdCert := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "365", "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
	if out, err := cmdCert.CombinedOutput(); err != nil {
		t.Fatalf("Failed to generate certificates: %v\n%s", err, out)
	}

	dbPath := filepath.Join(tmpDir, "gateon_test.db")

	// Copy and patch config files
	copyAndPatchConfig(t, filepath.Join(projectRoot, "tests/e2e/config"), configDir, env.Ports, certPath, keyPath, dbPath)

	return env
}

// Cleanup is retained for callers that defer it. Both the working directory
// and the built binary now live under t.TempDir(), which the testing package
// removes on its own, so there is nothing left for this to do.
func (env *TestEnv) Cleanup() {}

// exeSuffix returns the platform's executable extension so the built binary is
// launchable on Windows as well as Unix.
func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func getFreePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func copyAndPatchConfig(t *testing.T, srcDir, dstDir string, ports map[string]int, certPath, keyPath, dbPath string) {
	files := []string{"global.json", "routes.json", "services.json", "entrypoints.json", "middlewares.json", "tls_options.json"}
	for _, f := range files {
		src := filepath.Join(srcDir, f)
		dst := filepath.Join(dstDir, f)
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("Failed to read %s: %v", src, err)
		}

		s := string(data)
		// Patch ports
		s = patchPorts(s, ports)

		// Patch paths
		s = strings.ReplaceAll(s, "tests/e2e/cert.pem", certPath)
		s = strings.ReplaceAll(s, "tests/e2e/key.pem", keyPath)
		s = strings.ReplaceAll(s, "gateon_test.db", dbPath)

		if f == "global.json" {
			t.Logf("Patched global.json content: %s", s)
		}

		if err := os.WriteFile(dst, []byte(s), 0644); err != nil {
			t.Fatalf("Failed to write %s: %v", dst, err)
		}
	}
}

func patchPorts(s string, ports map[string]int) string {
	// Simple string replacement for common ports used in E2E configs
	s = replacePort(s, "8080", ports["mgmt"])
	s = replacePort(s, "8081", ports["http_plain"])
	s = replacePort(s, "8282", ports["http_tls"])
	s = replacePort(s, "8085", ports["grpc"])
	s = replacePort(s, "8086", ports["tcp"])
	s = replacePort(s, "8082", ports["mock_backend"])
	return s
}

func replacePort(s, oldPort string, newPort int) string {
	// Look for ":8080", "8080", "localhost:8080", etc.
	// This is a bit naive but should work for the controlled E2E configs.
	return strings.ReplaceAll(s, oldPort, strconv.Itoa(newPort))
}

func waitForPort(t *testing.T, port int) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("Timed out waiting for port %d", port)
}

// We need to import strings for replacePort
