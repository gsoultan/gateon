// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/server/handlers"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// testClientAddr stands in for the address the entrypoint resolves for a
// request (middleware.EntryPoint); the harness writes it into the request
// state the way that middleware does, which is where sign-in reads it.
const testClientAddr = "X-Test-Client-Addr"

// loginAPI serves sign-in over REST and gRPC, as run.go mounts them, with
// each request's client address taken from testClientAddr.
func loginAPI(t *testing.T) (url string, client *http.Client, grpcc gateonv1.ApiServiceClient) {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	dir := t.TempDir()
	mgr, err := auth.NewManager(filepath.Join(dir, "auth.db"), "12345678901234567890123456789012", logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.UpsertUser(&gateonv1.User{Username: "admin", Password: anonAdminPassword, Role: auth.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	svc := &api.ApiService{Auth: mgr, Globals: config.NewGlobalRegistry(filepath.Join(dir, "global.json"))}
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, svc, &handlers.Deps{AuthManager: mgr})
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(NewGRPCRBACInterceptor()))
	gateonv1.RegisterApiServiceServer(grpcServer, svc)
	t.Cleanup(grpcServer.Stop)
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs := &request.RequestState{ClientRemoteAddr: r.Header.Get(testClientAddr)}
		r = r.WithContext(request.WithState(r.Context(), rs))
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	srv := httptest.NewUnstartedServer(dispatch)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	conn, err := grpc.NewClient(strings.TrimPrefix(srv.URL, "https://"),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return srv.URL, srv.Client(), gateonv1.NewApiServiceClient(conn)
}

func restLogin(t *testing.T, client *http.Client, url, addr, password string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url+"/v1/login",
		strings.NewReader(`{"username":"admin","password":"`+password+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(testClientAddr, addr)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func grpcLogin(grpcc gateonv1.ApiServiceClient, addr, password string) error {
	ctx := metadata.AppendToOutgoingContext(context.Background(), strings.ToLower(testClientAddr), addr)
	_, err := grpcc.Login(ctx, &gateonv1.LoginRequest{Username: "admin", Password: password})
	return err
}

// TestAStrangerCannotLockTheAdminOutOverEitherTransport is M6 end to end:
// five wrong passwords for "admin" from one address, then the right password
// from another. It was refused as "account locked" on every transport,
// because the count was the username's.
func TestAStrangerCannotLockTheAdminOutOverEitherTransport(t *testing.T) {
	const attacker, owner = "203.0.113.9", "198.51.100.7"
	t.Run("REST", func(t *testing.T) {
		url, client, _ := loginAPI(t)
		for range auth.MaxFailedAttempts {
			if code := restLogin(t, client, url, attacker, "a-guess"); code != http.StatusUnauthorized {
				t.Fatalf("a wrong password: %d, want 401", code)
			}
		}
		if code := restLogin(t, client, url, owner, anonAdminPassword); code != http.StatusOK {
			t.Errorf("the admin from another address after a stranger's guesses: %d, want 200", code)
		}
		if code := restLogin(t, client, url, attacker, anonAdminPassword); code != http.StatusUnauthorized {
			t.Errorf("the stranger's sixth try, with the right password: %d, want 401 (locked)", code)
		}
	})
	t.Run("gRPC", func(t *testing.T) {
		_, _, grpcc := loginAPI(t)
		for range auth.MaxFailedAttempts {
			if err := grpcLogin(grpcc, attacker, "a-guess"); err == nil {
				t.Fatal("a wrong password was accepted")
			}
		}
		if err := grpcLogin(grpcc, owner, anonAdminPassword); err != nil {
			t.Errorf("the admin from another address after a stranger's guesses: %v", err)
		}
		if err := grpcLogin(grpcc, attacker, anonAdminPassword); err == nil || !strings.Contains(err.Error(), "locked") {
			t.Errorf("the stranger's sixth try, with the right password: err = %v, want locked", err)
		}
	})
}
