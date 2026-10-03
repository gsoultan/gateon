// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/server/handlers"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
)

const (
	anonAdminPassword = "the-owners-passphrase"
	anonChosen        = "Pwned-anon-1-long"
)

// anonymousAPI serves one ApiService the way run.go mounts it -- REST and
// Connect on the mux, gRPC by content type -- to a caller with no credential
// on a request the base handler marked as needing none: what it does when
// authentication is off and the API is reached on a data-plane entrypoint.
func anonymousAPI(t *testing.T) (url string, client *http.Client, grpcc gateonv1.ApiServiceClient, mgr *auth.Manager, adminID string) {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	dir := t.TempDir()
	mgr, err := auth.NewManager(filepath.Join(dir, "auth.db"), "12345678901234567890123456789012", logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	admin := &gateonv1.User{Username: "admin", Password: anonAdminPassword, Role: auth.RoleAdmin}
	if err := mgr.UpsertUser(admin); err != nil {
		t.Fatal(err)
	}
	svc := &api.ApiService{Auth: mgr, Globals: config.NewGlobalRegistry(filepath.Join(dir, "global.json"))}

	mux := http.NewServeMux()
	mux.Handle(apiConnectHandler(svc))
	handlers.RegisterRESTHandlers(mux, svc, &handlers.Deps{AuthManager: mgr})
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(NewGRPCRBACInterceptor()))
	gateonv1.RegisterApiServiceServer(grpcServer, svc)
	t.Cleanup(grpcServer.Stop)
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(middleware.WithAuthNotRequired(r.Context()))
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
	return srv.URL, srv.Client(), gateonv1.NewApiServiceClient(conn), mgr, admin.Id
}

func postJSON(t *testing.T, client *http.Client, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// requireAdminPasswordUnchanged is the real proof: whatever the answer said,
// the anonymous caller's password does not sign in and the admin's does.
func requireAdminPasswordUnchanged(t *testing.T, mgr *auth.Manager, transport string) {
	t.Helper()
	if _, _, err := mgr.Authenticate("admin", anonChosen, "198.51.100.1"); err == nil {
		t.Errorf("%s: an anonymous request set the administrator's password", transport)
	}
	if _, _, err := mgr.Authenticate("admin", anonAdminPassword, "198.51.100.2"); err != nil {
		t.Errorf("%s: the administrator's own password no longer works: %v", transport, err)
	}
}

// TestAnonymousChangePasswordIsRefusedOnEveryTransport is M3's remainder:
// with no caller, ApiService.ChangePassword treated "no claims" as "auth is
// off, anything goes" and reset the password of whatever id the request
// named -- the review reset the administrator's this way and signed in with
// it. It must never act without an authenticated caller.
func TestAnonymousChangePasswordIsRefusedOnEveryTransport(t *testing.T) {
	t.Run("REST", func(t *testing.T) {
		url, client, _, mgr, id := anonymousAPI(t)
		code, body := postJSON(t, client, url+"/v1/users/password", `{"id":"`+id+`","password":"`+anonChosen+`"}`)
		if code != http.StatusForbidden {
			t.Errorf("anonymous POST /v1/users/password: %d %s, want 403", code, body)
		}
		requireAdminPasswordUnchanged(t, mgr, "REST")
	})
	t.Run("gRPC", func(t *testing.T) {
		_, _, grpcc, mgr, id := anonymousAPI(t)
		_, err := grpcc.ChangePassword(context.Background(), &gateonv1.ChangePasswordRequest{Id: id, Password: anonChosen})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("anonymous gRPC ChangePassword: err = %v, want PermissionDenied", err)
		}
		requireAdminPasswordUnchanged(t, mgr, "gRPC")
	})
	t.Run("Connect", func(t *testing.T) {
		url, client, _, mgr, id := anonymousAPI(t)
		code, body := postJSON(t, client, url+"/"+gateonv1connect.ApiServiceName+"/ChangePassword",
			`{"id":"`+id+`","password":"`+anonChosen+`"}`)
		if code == http.StatusOK {
			t.Errorf("anonymous Connect ChangePassword answered 200: %s", body)
		}
		requireAdminPasswordUnchanged(t, mgr, "Connect")
	})
}
