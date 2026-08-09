// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func TestSecurityDashboard(t *testing.T) {
	// 1. Setup Environment
	env := SetupTestEnv(t)
	defer env.Cleanup()

	projectRoot, _ := filepath.Abs("../..")

	// Initialize Database and User
	t.Log("Initializing database...")
	dbPath := filepath.Join(env.Dir, "gateon_test.db")

	authMgr, err := auth.NewManager(dbPath, "12345678901234567890123456789012", logger.Default())
	if err != nil {
		t.Fatalf("Failed to init auth manager: %v", err)
	}
	err = authMgr.UpsertUser(&gateonv1.User{
		Username: "admin",
		Password: "password123",
		Role:     "admin",
	})
	authMgr.Close()
	if err != nil {
		t.Fatalf("Failed to create admin: %v", err)
	}

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
		fmt.Sprintf("GATEON_MANAGEMENT_PORT=%d", env.Ports["mgmt"]),
		"GATEON_TEST=1",
		"GATEON_PER_IP_METRICS=1",
		"GATEON_TRUSTED_PROXIES=127.0.0.1,::1",
	)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start Gateon: %v", err)
	}
	defer cmd.Process.Kill()

	// Wait for services to be ready
	waitForPort(t, env.Ports["http_tls"])
	waitForPort(t, env.Ports["mgmt"])

	// 4. Connect to Gateon API
	mgmtAddr := fmt.Sprintf("127.0.0.1:%d", env.Ports["mgmt"])
	conn, err := grpc.NewClient(mgmtAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to connect to Gateon API: %v", err)
	}
	defer conn.Close()
	apiClient := gateonv1.NewApiServiceClient(conn)

	// Login to get token
	loginResp, err := apiClient.Login(context.Background(), &gateonv1.LoginRequest{
		Username: "admin",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	token := loginResp.Token
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}

	httpsAddr := fmt.Sprintf("127.0.0.1:%d", env.Ports["http_tls"])

	// Helper to send request with spoofed IP and custom headers
	sendReq := func(method, urlStr, spoofedIP, userAgent string, headers map[string]string) (*http.Response, error) {
		// Create a NEW client and transport for each request to ensure unique JA4 (TLS) fingerprints
		// if the underlying OS/Go version allows it, or at least fresh state.
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DisableKeepAlives: true, // Force fresh handshake
			},
			Timeout: 5 * time.Second,
		}
		req, _ := http.NewRequest(method, urlStr, nil)
		if spoofedIP != "" {
			req.Header.Set("X-Forwarded-For", spoofedIP)
		}
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return client.Do(req)
	}

	// 5. Test Mitigation Funnel Accuracy
	t.Run("Mitigation Funnel Accuracy", func(t *testing.T) {
		spoofedIP := "10.0.0.1"
		userAgent := "FunnelTester/1.0"
		targetURL := "https://" + httpsAddr + "/test/echo"
		// Send 10 legitimate requests
		for i := 0; i < 10; i++ {
			resp, err := sendReq("GET", targetURL, spoofedIP, userAgent, nil)
			if err != nil {
				t.Fatalf("Legitimate request failed: %v", err)
			}
			resp.Body.Close()
		}

		// Send 5 malicious requests (WAF block)
		for i := 0; i < 5; i++ {
			maliciousURL := targetURL + "?id=" + url.QueryEscape("' OR 1=1 --")
			resp, err := sendReq("GET", maliciousURL, spoofedIP, userAgent, nil)
			if err != nil {
				t.Logf("Malicious request failed (network error): %v", err)
				continue
			}
			resp.Body.Close()
		}

		// Give some time for metrics to aggregate
		time.Sleep(10 * time.Second)

		// Get metrics from API
		metricsReq, err := http.NewRequestWithContext(ctx, "GET", "http://"+mgmtAddr+"/v1/diag/metrics?limit=100", nil)
		if err != nil {
			t.Fatalf("Failed to create metrics request: %v", err)
		}
		metricsReq.Header.Set("Authorization", "Bearer "+token)
		
		resp, err := httpClient.Do(metricsReq)
		if err != nil {
			t.Fatalf("Failed to get metrics: %v", err)
		}
		defer resp.Body.Close()

		var snap struct {
			MitigationFunnel struct {
				HTTPIngress    float64 `json:"httpIngress"`
				WAFBlocked     float64 `json:"wafBlocked"`
				Allowed        float64 `json:"allowed"`
				TotalMitigated float64 `json:"totalMitigated"`
			} `json:"mitigationFunnel"`
		}
		body, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(body, &snap); err != nil {
			t.Fatalf("Failed to decode metrics: %v\nBody: %s", err, string(body))
		}

		t.Logf("Funnel (SYNC): Ingress=%.0f, WAFBlocked=%.0f, Allowed=%.0f, TotalMitigated=%.0f",
			snap.MitigationFunnel.HTTPIngress, snap.MitigationFunnel.WAFBlocked,
			snap.MitigationFunnel.Allowed, snap.MitigationFunnel.TotalMitigated)

		if snap.MitigationFunnel.HTTPIngress == 0 {
			t.Errorf("Ingress requests still 0 in funnel. Invariant check skipped.")
		} else {
			// Verify invariant: Allowed + TotalMitigated == HTTPIngress
			diff := snap.MitigationFunnel.HTTPIngress - (snap.MitigationFunnel.Allowed + snap.MitigationFunnel.TotalMitigated)
			if diff > 0.001 || diff < -0.001 {
				t.Errorf("Funnel invariant failed: Ingress(%.0f) != Allowed(%.0f) + TotalMitigated(%.0f)",
					snap.MitigationFunnel.HTTPIngress, snap.MitigationFunnel.Allowed, snap.MitigationFunnel.TotalMitigated)
			}
		}
	})

	// 6. Test Mitigation Removal
	t.Run("Mitigation Removal and Immediate Release", func(t *testing.T) {
		spoofedIP := "10.0.0.2"
		userAgent := "ReleaseTester/1.0"

		// 1. Manually block our spoofed IP
		blockResp, err := apiClient.ApplyRecommendation(ctx, &gateonv1.ApplyRecommendationRequest{
			AnomalyType: "high_traffic",
			Source:      spoofedIP,
		})
		if err != nil {
			t.Fatalf("Failed to apply block recommendation: %v", err)
		}
		if !blockResp.Success {
			t.Fatalf("Block recommendation failed: %s", blockResp.Message)
		}
		t.Logf("IP %s blocked manually", spoofedIP)

		// 2. Verify we are blocked on a valid route
		resp, err := sendReq("GET", "https://"+httpsAddr+"/test/echo", spoofedIP, userAgent, nil)
		if err != nil {
			t.Fatalf("Request failed while blocked: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("Request status while blocked: %d, Body: %s", resp.StatusCode, string(body))
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403 while blocked, got %d", resp.StatusCode)
		}

		// 3. Remove mitigation
		unblockResp, err := apiClient.RemoveMitigatedThreat(ctx, &gateonv1.RemoveMitigatedThreatRequest{
			Source: spoofedIP,
		})
		if err != nil {
			t.Fatalf("Failed to remove mitigated threat: %v", err)
		}
		if !unblockResp.Success {
			t.Fatalf("Remove mitigated threat failed: %s", unblockResp.Message)
		}
		t.Logf("Mitigation removed for %s", spoofedIP)

		// Wait a bit for invalidation and reputation reset
		time.Sleep(5 * time.Second)

		// 4. Verify we are immediately released on the same route
		resp, err = sendReq("GET", "https://"+httpsAddr+"/test/echo", spoofedIP, userAgent, nil)
		if err != nil {
			t.Fatalf("Request failed after release: %v", err)
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("Request status after release: %d, Body: %s", resp.StatusCode, string(body))
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 after release, got %d", resp.StatusCode)
		}
	})

	// 7. Test Mark as False Positive (WAF Exclusion)
	t.Run("Mark as Positive (WAF Exclusion)", func(t *testing.T) {
		spoofedIP := "10.0.0.3"
		userAgent := "WafExclusionTester/1.0"
		// Use a payload that triggers CRS SQLi in Cookie header (Phase 1)
		headers := map[string]string{
			"Cookie": "session=1' OR '1'='1",
		}

		// 1. Trigger a WAF violation
		resp, err := sendReq("GET", "https://"+httpsAddr+"/test/echo", spoofedIP, userAgent, headers)
		if err != nil {
			t.Fatalf("Failed to trigger WAF: %v", err)
		}
		resp.Body.Close()
		
		time.Sleep(10 * time.Second) // Wait for threat to be recorded in DB

		// Look specifically for WAF violations with rule IDs
		threatsResp, err := apiClient.ListSecurityThreats(ctx, &gateonv1.ListSecurityThreatsRequest{
			Limit: 100,
			Status: "all",
		})
		if err != nil {
			t.Fatalf("Failed to list threats: %v", err)
		}
		
		var threat *gateonv1.Anomaly
		for _, th := range threatsResp.Threats {
			if th.Source == spoofedIP && th.TriggeredRules != "" && th.TriggeredRules != "[]" {
				threat = th
				break
			}
		}

		if threat == nil {
			t.Logf("Total threats found: %d", len(threatsResp.Threats))
			for _, th := range threatsResp.Threats {
				t.Logf("Threat: %s Source: %s Rules: %s", th.Type, th.Source, th.TriggeredRules)
			}
			t.Fatalf("No WAF threats with rule IDs found for %s", spoofedIP)
		}
		t.Logf("Found WAF threat: %s (ID: %s) Rules: %s", threat.Type, threat.Id, threat.TriggeredRules)

		// 2. Apply "False Positive" resolution
		resolveResp, err := apiClient.ApplyRecommendation(ctx, &gateonv1.ApplyRecommendationRequest{
			AnomalyType: "waf_block",
			Source:      threat.Source,
			ThreatId:    threat.Id,
		})
		if err != nil {
			t.Fatalf("Failed to apply WAF exclusion: %v", err)
		}
		if !resolveResp.Success {
			t.Fatalf("WAF exclusion failed: %s", resolveResp.Message)
		}

		// Wait for rule to apply and invalidate
		time.Sleep(5 * time.Second)

		// 3. Verify previously blocked request now passes
		resp, err = sendReq("GET", "https://"+httpsAddr+"/test/echo", spoofedIP, userAgent, headers)
		if err != nil {
			t.Fatalf("Request failed after exclusion: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("Request status after exclusion: %d, Body: %s", resp.StatusCode, string(body))
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 after WAF exclusion, got %d", resp.StatusCode)
		}
	})
}
