// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func TestTechDiscovery(t *testing.T) {
	// 1. Setup Environment
	env := SetupTestEnv(t)
	defer env.Cleanup()

	projectRoot, _ := filepath.Abs("../..")

	// 1.5. Initialize Database and User
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

	// 2. Build and Start Mock Backend. Built into the test's temp dir, not the
	// repository root: a test must not leave binaries in the checkout, and a
	// subtest name contains a '/' that would make the -o path invalid.
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

	// Wait for mock backend to be ready
	waitForPort(t, env.Ports["mock_backend"])

	// 3. Start Gateon (in API mode)
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
	waitForPort(t, env.Ports["mgmt"])

	// 4. Connect to Gateon API
	mgmtAddr := fmt.Sprintf("127.0.0.1:%d", env.Ports["mgmt"])
	conn, err := grpc.NewClient(mgmtAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to connect to Gateon API: %v", err)
	}
	defer conn.Close()
	client := gateonv1.NewApiServiceClient(conn)

	// 4.5 Login to get token
	loginResp, err := client.Login(context.Background(), &gateonv1.LoginRequest{
		Username: "admin",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+loginResp.Token))

	mockAddr := fmt.Sprintf("http://127.0.0.1:%d", env.Ports["mock_backend"])

	// 5. Test pgAdmin Discovery
	t.Run("pgAdmin Discovery", func(t *testing.T) {
		resp, err := client.DiscoverTech(ctx, &gateonv1.DiscoverTechRequest{
			Url: mockAddr + "/pgadmin4/",
		})
		if err != nil {
			t.Fatalf("DiscoverTech failed: %v", err)
		}
		if resp.Tech != "pgadmin4" {
			t.Errorf("Expected tech pgadmin4, got %s", resp.Tech)
		}
		if len(resp.Recommendations) == 0 {
			t.Error("Expected recommendations for pgAdmin4")
		}
		t.Logf("Detected: %s, Recommendations: %v", resp.Tech, resp.Recommendations)
	})

	// 6. Test Synology Discovery
	t.Run("Synology Discovery", func(t *testing.T) {
		resp, err := client.DiscoverTech(ctx, &gateonv1.DiscoverTechRequest{
			Url: mockAddr + "/synology/",
		})
		if err != nil {
			t.Fatalf("DiscoverTech failed: %v", err)
		}
		if resp.Tech != "synology_dsm" {
			t.Errorf("Expected tech synology_dsm, got %s", resp.Tech)
		}
		t.Logf("Detected: %s, Recommendations: %v", resp.Tech, resp.Recommendations)
	})

	// 7. Test gRPC Discovery
	t.Run("gRPC Discovery", func(t *testing.T) {
		resp, err := client.DiscoverTech(ctx, &gateonv1.DiscoverTechRequest{
			Url: mockAddr + "/grpc",
		})
		if err != nil {
			t.Fatalf("DiscoverTech failed: %v", err)
		}
		if resp.Tech != "grpc" {
			t.Errorf("Expected tech grpc, got %s", resp.Tech)
		}
		t.Logf("Detected: %s, Recommendations: %v", resp.Tech, resp.Recommendations)
	})
}
