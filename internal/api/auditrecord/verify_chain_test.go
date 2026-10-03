// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auditrecord_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	mwauth "github.com/gsoultan/gateon/internal/middleware/auth"
	"github.com/gsoultan/gateon/internal/server"
	"github.com/gsoultan/gateon/internal/server/handlers"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
)

// verifyAPI serves ApiService over REST, Connect and gRPC, mounted as run.go
// mounts them, to a caller already identified as claims.
func verifyAPI(t *testing.T, claims *auth.Claims) (base string, client *http.Client, grpcc gateonv1.ApiServiceClient) {
	t.Helper()
	svc := &api.ApiService{Globals: config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))}
	mux := http.NewServeMux()
	mux.Handle(gateonv1connect.NewApiServiceHandler(api.NewConnectHandler(svc),
		connect.WithInterceptors(server.NewConnectRBACInterceptor(), api.StatusInterceptor())))
	handlers.RegisterRESTHandlers(mux, svc, &handlers.Deps{})
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(server.NewGRPCRBACInterceptor()))
	gateonv1.RegisterApiServiceServer(grpcServer, svc)
	t.Cleanup(grpcServer.Stop)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(mwauth.InjectContext(r.Context(), claims))
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	}))
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

var (
	adminClaims  = &auth.Claims{ID: "admin-1", Username: "admin", Role: auth.RoleAdmin}
	viewerClaims = &auth.Claims{ID: "viewer-1", Username: "viewer", Role: auth.RoleViewer}
)

// signedEntries turns signing on, writes n entries, and returns a time just
// before the first of them.
func signedEntries(t *testing.T, n int) time.Time {
	t.Helper()
	audit.UpdateConfig(&gateonv1.AuditConfig{Enabled: true, SignEntries: true, SignatureKey: strings.Repeat("s", 64)})
	t.Cleanup(func() { audit.UpdateConfig(&gateonv1.AuditConfig{Enabled: true}) })
	from := time.Now().Add(-time.Millisecond)
	id := uniqueID(t)
	for range n {
		audit.Log(context.Background(), "admin", "update", "global_config", "verify "+id, "198.51.100.7")
	}
	return from
}

func httpCall(t *testing.T, client *http.Client, method, target, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, target, bytes.NewBufferString(body))
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
	return resp.StatusCode, out
}

type verifyAnswer struct {
	Intact  bool  `json:"intact"`
	Checked int32 `json:"checked"`
}

// TestAnAdministratorVerifiesTheChainOnEveryTransport is M8's other half:
// VerifyChain had no caller, so the HMAC chain was computed and never
// checked. It is answered over REST, Connect and gRPC alike.
func TestAnAdministratorVerifiesTheChainOnEveryTransport(t *testing.T) {
	base, client, grpcc := verifyAPI(t, adminClaims)
	from := signedEntries(t, 3).UTC().Format(time.RFC3339Nano)

	t.Run("REST", func(t *testing.T) {
		code, body := httpCall(t, client, http.MethodGet, base+"/v1/audit/verify?from="+url.QueryEscape(from), "")
		var a verifyAnswer
		if code != http.StatusOK || json.Unmarshal(body, &a) != nil || !a.Intact || a.Checked < 3 {
			t.Fatalf("GET /v1/audit/verify: %d %s, want 200, intact, at least 3 checked", code, body)
		}
	})
	t.Run("Connect", func(t *testing.T) {
		code, body := httpCall(t, client, http.MethodPost, base+"/"+gateonv1connect.ApiServiceName+"/VerifyAuditChain",
			`{"from":"`+from+`"}`)
		var a verifyAnswer
		if code != http.StatusOK || json.Unmarshal(body, &a) != nil || !a.Intact || a.Checked < 3 {
			t.Fatalf("Connect VerifyAuditChain: %d %s, want 200, intact, at least 3 checked", code, body)
		}
	})
	t.Run("gRPC", func(t *testing.T) {
		resp, err := grpcc.VerifyAuditChain(context.Background(), &gateonv1.VerifyAuditChainRequest{From: from})
		if err != nil || !resp.GetIntact() || resp.GetChecked() < 3 || !resp.GetComplete() {
			t.Fatalf("gRPC VerifyAuditChain: %v %v, want intact, complete, at least 3 checked", resp, err)
		}
	})
}

// TestVerifyingTheChainNeedsAnAdministrator: a viewer reads the audit log
// but does not run the verification.
func TestVerifyingTheChainNeedsAnAdministrator(t *testing.T) {
	base, client, grpcc := verifyAPI(t, viewerClaims)
	if code, body := httpCall(t, client, http.MethodGet, base+"/v1/audit/verify", ""); code != http.StatusForbidden {
		t.Errorf("a viewer's GET /v1/audit/verify: %d %s, want 403", code, body)
	}
	if _, err := grpcc.VerifyAuditChain(context.Background(), &gateonv1.VerifyAuditChainRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a viewer's gRPC VerifyAuditChain: %v, want PermissionDenied", err)
	}
}

// TestVerifyingWithSigningOffSaysWhy rather than reporting a broken chain.
func TestVerifyingWithSigningOffSaysWhy(t *testing.T) {
	base, client, grpcc := verifyAPI(t, adminClaims)
	audit.UpdateConfig(&gateonv1.AuditConfig{Enabled: true})
	_, err := grpcc.VerifyAuditChain(context.Background(), &gateonv1.VerifyAuditChainRequest{})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "sign_entries") {
		t.Errorf("verifying with signing off: %v, want FailedPrecondition naming sign_entries", err)
	}
	// A refusal over REST too, not the 500 every unmapped code became.
	if code, body := httpCall(t, client, http.MethodGet, base+"/v1/audit/verify", ""); code != http.StatusBadRequest ||
		!strings.Contains(string(body), "sign_entries") {
		t.Errorf("GET /v1/audit/verify with signing off: %d %s, want 400 naming sign_entries", code, body)
	}
	if _, err := grpcc.VerifyAuditChain(context.Background(), &gateonv1.VerifyAuditChainRequest{From: "yesterday"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("a malformed from: %v, want InvalidArgument", err)
	}
}
