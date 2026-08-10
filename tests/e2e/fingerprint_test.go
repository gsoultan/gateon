// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package e2e

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestFingerprintBlocking(t *testing.T) {
	// 1. Setup Environment
	env := SetupTestEnv(t)
	defer env.Cleanup()

	projectRoot, _ := filepath.Abs("../..")

	// 2. Start Gateon
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
		"GATEON_ENABLE_TEST_REPUTATION=1",
	)

	// Redirect output for debugging
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start Gateon: %v", err)
	}
	defer cmd.Process.Kill()

	// 3. Start the mock backend at allocated port
	// Built into the test's temp dir, not the repository root: a test must not
	// leave binaries in the checkout, and a subtest name contains a '/' that
	// would make the -o path invalid.
	mockBinaryPath := filepath.Join(env.Dir, "mock_backend"+exeSuffix())
	t.Logf("Building mock backend into %s...", mockBinaryPath)
	cmdMockBuild := exec.Command("go", "build", "-o", mockBinaryPath, "tests/e2e/mock_backend/main.go")
	cmdMockBuild.Dir = projectRoot
	if out, err := cmdMockBuild.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build mock backend: %v\n%s", err, out)
	}

	mockBackend := exec.Command(mockBinaryPath)
	mockBackend.Dir = projectRoot
	mockBackend.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", env.Ports["mock_backend"]))
	if err := mockBackend.Start(); err != nil {
		t.Fatalf("Failed to start mock backend: %v", err)
	}
	defer mockBackend.Process.Kill()

	// Wait for Gateon and mock backend to be ready
	waitForPort(t, env.Ports["http_tls"])
	waitForPort(t, env.Ports["mock_backend"])

	// 4. Test Clients
	attackerClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			},
		},
	}
	normalClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
			},
		},
	}

	httpsAddr := fmt.Sprintf("localhost:%d", env.Ports["http_tls"])
	targetURL := "https://" + httpsAddr + "/test"
	attackerUA := "Mozilla/5.0 (compatible; AttackerBot/1.0)"
	normalUA := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	sharedIP := "1.2.3.4"

	// Client A: Attacker (sends LFI/RCE attempt)
	t.Run("Attacker gets blocked", func(t *testing.T) {
		for i := 0; i < 15; i++ {
			req, _ := http.NewRequest("GET", targetURL+"?file=/etc/passwd&exec=/bin/ls", nil)
			req.Header.Set("User-Agent", attackerUA)
			req.Header.Set("X-Forwarded-For", sharedIP)

			resp, err := attackerClient.Do(req)
			if err != nil {
				t.Logf("Attempt %d: %v", i, err)
				continue
			}
			t.Logf("Attempt %d: Status %d", i, resp.StatusCode)
			resp.Body.Close()
			time.Sleep(200 * time.Millisecond) // Wait for threat pipeline
		}

		// Wait for reputation update to propagate
		time.Sleep(2 * time.Second)

		// Now check if Client A is blocked even with a normal request
		req, _ := http.NewRequest("GET", targetURL, nil)
		req.Header.Set("User-Agent", attackerUA)
		req.Header.Set("X-Forwarded-For", sharedIP)

		resp, err := attackerClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected attacker to be blocked (403), got %d", resp.StatusCode)
		} else {
			t.Log("Attacker successfully blocked by reputation")
		}
	})

	// Client B: Normal (sends normal request from same IP)
	t.Run("Normal user stays allowed", func(t *testing.T) {
		req, _ := http.NewRequest("GET", targetURL, nil)
		req.Header.Set("User-Agent", normalUA)
		req.Header.Set("X-Forwarded-For", sharedIP)

		resp, err := normalClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected normal user to be allowed (200), got %d", resp.StatusCode)
			body, _ := io.ReadAll(resp.Body)
			t.Logf("Response body: %s", string(body))
		} else {
			t.Log("Normal user successfully allowed despite sharing IP with attacker")
		}
	})
}
