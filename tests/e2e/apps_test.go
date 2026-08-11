// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppsProxying(t *testing.T) {
	// 1. Setup Environment
	env := SetupTestEnv(t)
	defer env.Cleanup()

	projectRoot, _ := filepath.Abs("../..")

	// 2. Build and Start Mock Backend
	mockBinaryName := "mock_backend_" + t.Name()
	mockBinaryPath := filepath.Join(projectRoot, mockBinaryName)
	t.Logf("Building mock backend: %s...", mockBinaryName)
	cmdMockBuild := exec.Command("go", "build", "-o", mockBinaryName, "tests/e2e/mock_backend/main.go")
	cmdMockBuild.Dir = projectRoot
	if out, err := cmdMockBuild.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build mock backend: %v\n%s", err, out)
	}
	defer os.Remove(mockBinaryPath)

	mockBackend := exec.Command(mockBinaryPath)
	mockBackend.Dir = projectRoot
	mockBackend.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", env.Ports["mock_backend"]))

	if err := mockBackend.Start(); err != nil {
		t.Fatalf("Failed to start mock backend: %v", err)
	}
	defer mockBackend.Process.Kill()

	// Wait for mock backend to be ready
	waitForPort(t, env.Ports["mock_backend"])

	// 3. Start Gateon
	cmd := exec.Command(env.BinaryPath)
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GLOBAL_CONFIG_FILE=%s", filepath.Join(env.Dir, "config/global.json")),
		fmt.Sprintf("ROUTES_FILE=%s", filepath.Join(env.Dir, "config/routes.json")),
		fmt.Sprintf("SERVICES_FILE=%s", filepath.Join(env.Dir, "config/services.json")),
		fmt.Sprintf("ENTRYPOINTS_FILE=%s", filepath.Join(env.Dir, "config/entrypoints.json")),
		fmt.Sprintf("MIDDLEWARES_FILE=%s", filepath.Join(env.Dir, "config/middlewares.json")),
		fmt.Sprintf("TLS_OPTIONS_FILE=%s", filepath.Join(env.Dir, "config/tls_options.json")),
		"GATEON_TRUSTED_PROXIES=127.0.0.1,::1",
		"GATEON_TEST=1",
	)

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start Gateon: %v", err)
	}
	defer cmd.Process.Kill()

	// Wait for Gateon to be ready
	waitForPort(t, env.Ports["http_tls"])

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	httpsAddr := fmt.Sprintf("127.0.0.1:%d", env.Ports["http_tls"])

	// 4. Test pgAdmin Scenario
	t.Run("pgAdmin Proxying", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://"+httpsAddr+"/pgadmin4/browser/", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to request pgAdmin: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var data map[string]interface{}
		body, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(body, &data); err != nil {
			t.Fatalf("Failed to decode response: %v\nBody: %s", err, string(body))
		}
		t.Logf("Response body: %s", string(body))

		headers := data["headers"].(map[string]interface{})

		// Verify pgAdmin specific headers injected by middleware
		if headers["X-Script-Name"] != "/pgadmin4" {
			t.Errorf("Expected X-Script-Name: /pgadmin4, got %v", headers["X-Script-Name"])
		}
		if headers["X-Scheme"] != "https" {
			t.Errorf("Expected X-Scheme: https, got %v", headers["X-Scheme"])
		}

		// Verify standard proxy headers
		if headers["X-Forwarded-Proto"] != "https" {
			t.Errorf("Expected X-Forwarded-Proto: https, got %v", headers["X-Forwarded-Proto"])
		}
		t.Log("pgAdmin headers verified successfully")
	})

	// 5. Test Synology Scenario (WebSocket)
	t.Run("Synology WebSocket Proxying", func(t *testing.T) {
		// This used to stall on Linux and pass on darwin: the gateway accepted
		// the TLS connection and then wrote nothing, so the client read until
		// its deadline. The cause was internal/phantom, which is Linux-only —
		// it wrapped every accepted connection in an iouringConn, so a hijacked
		// WebSocket did its reads and writes through io_uring instead of the
		// *net.TCPConn the hijack handed back. It is now opt-in behind
		// GATEON_PHANTOM=1 and this passes on both platforms, so the test runs
		// everywhere rather than being skipped on the one platform that caught
		// a real bug.
		dialer := &tls.Dialer{
			Config: &tls.Config{InsecureSkipVerify: true},
		}
		conn, err := dialer.Dial("tcp", httpsAddr)
		if err != nil {
			t.Fatalf("Failed to connect to Gateon: %v", err)
		}
		defer conn.Close()

		// This is a hand-rolled upgrade over a raw connection, so nothing here
		// times out on its own: if the gateway does not answer, ReadString
		// blocks until the whole package hits `go test`'s 10-minute limit and
		// the panic names the package rather than this test. A deadline turns
		// that into an immediate, attributable failure.
		if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
			t.Fatalf("Failed to set connection deadline: %v", err)
		}

		// Send WebSocket upgrade request
		fmt.Fprintf(conn, "GET /synology/ws HTTP/1.1\r\n")
		fmt.Fprintf(conn, "Host: %s\r\n", httpsAddr)
		fmt.Fprintf(conn, "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n")
		fmt.Fprintf(conn, "Upgrade: websocket\r\n")
		fmt.Fprintf(conn, "Connection: Upgrade\r\n")
		fmt.Fprintf(conn, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
		fmt.Fprintf(conn, "Sec-WebSocket-Version: 13\r\n")
		fmt.Fprintf(conn, "\r\n")

		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
		if !strings.Contains(line, "101 Switching Protocols") {
			t.Errorf("Expected 101 Switching Protocols, got %s", line)
		}

		// Skip other headers
		for {
			line, _ = reader.ReadString('\n')
			if line == "\r\n" {
				break
			}
		}

		// Test bidirectional communication (Fast!)
		message := "Hello WebSocket\n"
		fmt.Fprint(conn, message)

		reply, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read reply: %v", err)
		}
		expected := "ECHO: " + message
		if reply != expected {
			t.Errorf("Expected %q, got %q", expected, reply)
		}
		t.Log("Synology WebSocket proxying verified successfully")
	})

	// 6. Test Security (WAF)
	t.Run("Security Blocking", func(t *testing.T) {
		// Malicious request to pgAdmin path
		req, _ := http.NewRequest("GET", "https://"+httpsAddr+"/pgadmin4/?exec=/bin/sh", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send malicious request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected status 403 for malicious request, got %d", resp.StatusCode)
		}
		t.Log("Security blocking verified successfully")
	})
}
