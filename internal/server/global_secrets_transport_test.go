// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/server/handlers"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
)

// secretLadenConfig puts a distinct random value in every credential field of
// the global configuration, and returns the values. It is written out field by
// field rather than generated from the table the fix uses, so a field missing
// from that table shows up here as a leak.
func secretLadenConfig(t *testing.T) (*gateonv1.GlobalConfig, []string) {
	t.Helper()
	var values []string
	r := func() string {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		v := "S3CR3T" + hex.EncodeToString(b)
		values = append(values, v)
		return v
	}
	c := &gateonv1.GlobalConfig{
		Auth: &gateonv1.AuthConfig{Enabled: true, PasetoSecret: r() + "-at-least-32-bytes",
			DatabaseUrl: "postgres://gateon:" + r() + "@db.internal:5432/gateon",
			DatabaseConfig: &gateonv1.DatabaseConfig{Driver: "postgres", Host: "db.internal", Port: 5432,
				User: "gateon", Password: r(), Database: "gateon"}},
		Audit: &gateonv1.AuditConfig{Enabled: true, SignEntries: true, SignatureKey: r(),
			DatabaseUrl:    "postgres://audit:" + r() + "@audit.internal:5432/audit",
			DatabaseConfig: &gateonv1.DatabaseConfig{Driver: "postgres", Host: "audit.internal", Port: 5432, Password: r()}},
		Redis: &gateonv1.RedisConfig{Addr: "redis.internal:6379", Password: r()},
		Ha:    &gateonv1.HaConfig{AuthPass: r()},
		Geoip: &gateonv1.GeoIPConfig{MaxmindLicenseKey: r()},
		Management: &gateonv1.ManagementConfig{Bind: "127.0.0.1", Port: "8080", Gitops: &gateonv1.GitOpsConfig{
			RepositoryUrl: "https://deploy:" + r() + "@git.internal/org/config.git", AuthToken: r()}},
		Waf: &gateonv1.WafConfig{BotManagement: &gateonv1.BotManagementConfig{SecretKey: r()}},
		SecurityAdvanced: &gateonv1.SecurityAdvancedConfig{
			Deception: &gateonv1.DeceptionConfig{CanaryToken: r()},
			Pow:       &gateonv1.PowConfig{Secret: r()},
			IpReputation: &gateonv1.IPReputationConfig{Integrations: []*gateonv1.IPReputationIntegration{
				{Id: "rep-1", Name: "AbuseIPDB", Type: "abuseipdb", ApiKey: r()},
				{Id: "rep-2", Name: "VirusTotal", Type: "virustotal", ApiKey: r()},
			}},
		},
		Alerting: &gateonv1.AlertingConfig{Dispatchers: []*gateonv1.AlertDispatcher{
			{Id: "d-1", Name: "ops", Type: "slack", WebhookUrl: "https://hooks.slack.com/services/" + r()},
			{Id: "d-2", Name: "on-call", Type: "telegram", TelegramBotToken: r(), TelegramChatId: "42"},
		}},
	}
	return c, values
}

// adminAPI serves one ApiService the way run.go mounts it -- REST on the mux,
// Connect beside it, gRPC by content type -- to a caller PasetoAuth has
// already identified as an administrator.
type adminAPI struct {
	url  string
	http *http.Client
	grpc gateonv1.ApiServiceClient
	path string
	reg  *config.GlobalRegistry
}

func newAdminAPI(t *testing.T) (*adminAPI, []string) {
	t.Helper()
	return newAPIAs(t, &auth.Claims{ID: "admin-1", Username: "admin", Role: auth.RoleAdmin})
}

// newAPIAs is newAdminAPI for a caller PasetoAuth identified as claims.
func newAPIAs(t *testing.T, claims *auth.Claims) (*adminAPI, []string) {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	path := filepath.Join(t.TempDir(), "global.json")
	reg := config.NewGlobalRegistry(path)
	conf, values := secretLadenConfig(t)
	if err := reg.Update(context.Background(), conf); err != nil {
		t.Fatalf("store the secrets: %v", err)
	}
	svc := &api.ApiService{Globals: reg}

	mux := http.NewServeMux()
	mux.Handle(apiConnectHandler(svc))
	handlers.RegisterRESTHandlers(mux, svc, &handlers.Deps{})
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(NewGRPCRBACInterceptor()))
	gateonv1.RegisterApiServiceServer(grpcServer, svc)
	t.Cleanup(grpcServer.Stop)
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	srv := httptest.NewUnstartedServer(withClaims(dispatch, claims))
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
	return &adminAPI{url: srv.URL, http: srv.Client(), grpc: gateonv1.NewApiServiceClient(conn), path: path, reg: reg}, values
}

func (a *adminAPI) do(t *testing.T, method, path, contentType string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, a.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := a.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

// snapshot is the stored configuration: the live one and the file.
func (a *adminAPI) snapshot(t *testing.T) (*gateonv1.GlobalConfig, []byte) {
	t.Helper()
	live, ok := proto.Clone(a.reg.Get(context.Background())).(*gateonv1.GlobalConfig)
	if !ok {
		t.Fatal("clone")
	}
	file, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	return live, file
}

func requireNoSecret(t *testing.T, transport string, got []byte, values []string) {
	t.Helper()
	for _, v := range values {
		if bytes.Contains(got, []byte(v)) {
			t.Errorf("%s handed an administrator the stored secret %q", transport, v)
		}
	}
}

func (a *adminAPI) requireUnchanged(t *testing.T, transport string, live *gateonv1.GlobalConfig, file []byte) {
	t.Helper()
	gotLive, gotFile := a.snapshot(t)
	if !proto.Equal(gotLive, live) {
		t.Errorf("after %s read and saved back unchanged, the live config differs:\n got %v\nwant %v", transport, gotLive, live)
	}
	if !bytes.Equal(gotFile, file) {
		t.Errorf("after %s read and saved back unchanged, global.json differs:\n got %s\nwant %s", transport, gotFile, file)
	}
}

// TestGlobalConfigReadGivesAnAdministratorNoStoredSecret is the defect: with a
// distinct secret stored in every credential field, an administrator's read of
// the global configuration -- over REST, Connect and gRPC -- carries none of
// them, and saving back what was read, unchanged, leaves every stored secret
// exactly as it was. A stolen administrator session used to read the PASETO
// key, with which it could mint a session for any account that outlived the
// password and a sign-out, along with every other credential here.
func TestGlobalConfigReadGivesAnAdministratorNoStoredSecret(t *testing.T) {
	t.Run("REST", func(t *testing.T) {
		a, values := newAdminAPI(t)
		live, file := a.snapshot(t)
		code, body := a.do(t, http.MethodGet, "/v1/global", "", nil)
		if code != http.StatusOK {
			t.Fatalf("GET /v1/global: %d %s", code, body)
		}
		requireNoSecret(t, "GET /v1/global", body, values)
		if code, out := a.do(t, http.MethodPut, "/v1/global", "application/json", body); code != http.StatusOK {
			t.Fatalf("PUT /v1/global of the unchanged read: %d %s", code, out)
		}
		a.requireUnchanged(t, "REST", live, file)
	})
	t.Run("Connect", func(t *testing.T) {
		a, values := newAdminAPI(t)
		code, body := a.do(t, http.MethodPost, "/"+gateonv1connect.ApiServiceName+"/GetGlobalConfig", "application/json", []byte("{}"))
		requireNoSecret(t, "Connect GetGlobalConfig", body, values)
		// The Connect handler does not serve this RPC today (it answers
		// unimplemented); if it ever does, it must serve the same view.
		if code != http.StatusOK && code != http.StatusNotFound && !bytes.Contains(body, []byte("unimplemented")) {
			t.Fatalf("Connect GetGlobalConfig answered %d %s", code, body)
		}
	})
	t.Run("gRPC", func(t *testing.T) {
		a, values := newAdminAPI(t)
		live, file := a.snapshot(t)
		resp, err := a.grpc.GetGlobalConfig(context.Background(), &gateonv1.GetGlobalConfigRequest{})
		if err != nil {
			t.Fatalf("gRPC GetGlobalConfig: %v", err)
		}
		wire, err := proto.Marshal(resp)
		if err != nil {
			t.Fatal(err)
		}
		requireNoSecret(t, "gRPC GetGlobalConfig", wire, values)
		if _, err := a.grpc.UpdateGlobalConfig(context.Background(),
			&gateonv1.UpdateGlobalConfigRequest{Config: resp.GetConfig()}); err != nil {
			t.Fatalf("gRPC UpdateGlobalConfig of the unchanged read: %v", err)
		}
		a.requireUnchanged(t, "gRPC", live, file)
	})
}
