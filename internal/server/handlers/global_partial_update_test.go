// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// storedGlobalConfig is a configured gateway: a Postgres-backed auth database,
// a management plane restricted to one network, a certificate, and a WAF.
func storedGlobalConfig() *gateonv1.GlobalConfig {
	return &gateonv1.GlobalConfig{
		Auth: &gateonv1.AuthConfig{
			Enabled:      true,
			PasetoSecret: "PASETO-KEY-32-BYTES-LONG-SECRET!",
			DatabaseConfig: &gateonv1.DatabaseConfig{
				Driver: "postgres", Host: "db.internal", User: "gateon", Password: "db-pass", Database: "gateon",
			},
		},
		Management: &gateonv1.ManagementConfig{Bind: "10.0.0.5", Port: "9443", AllowedIps: []string{"10.0.0.0/8"}},
		Tls: &gateonv1.TlsConfig{Enabled: true, Certificates: []*gateonv1.Certificate{
			{Id: "prod-cert", CertFile: "/etc/gateon/certs/prod.crt", KeyFile: "/etc/gateon/certs/prod.key"},
		}},
		Waf:     &gateonv1.WafConfig{Enabled: true, UseCrs: true, ParanoiaLevel: 2},
		Profile: "minimal",
	}
}

// TestGlobalUpdateKeepsTheSectionsItWasNotSent sends PUT /v1/global the body
// doc/waf-origins.md tells an operator to send.
//
// The handler used to store the decoded body as the whole configuration, so
// every section the body left out was deleted: the auth block (its database
// settings and session key), the management allowlist, every certificate.
// Nothing fails at the time. On the next restart the bootstrap finds no auth
// database, generates a new session key and points auth at a fresh local
// SQLite file -- which has no administrator, so the first-run Setup endpoint
// is open again -- while the management plane falls back to its default of
// listening on every interface for every address.
func TestGlobalUpdateKeepsTheSectionsItWasNotSent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "global.json")
	reg := config.NewGlobalRegistry(path)
	if err := reg.Update(context.Background(), storedGlobalConfig()); err != nil {
		t.Fatalf("seeding the stored config: %v", err)
	}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, &globalsAPI{store: reg}, &Deps{})

	body := `{"waf": {"enabled": true, "origins": ["example.com", "api.example.com"]}}`
	req := httptest.NewRequest(http.MethodPut, "/v1/global", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "admin-1", Username: "admin", Role: auth.RoleAdmin}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT /v1/global answered %d: %s", rr.Code, rr.Body.String())
	}

	// What the next process start will read, not only what is in memory.
	persisted := config.NewGlobalRegistry(path).Get(context.Background())
	for name, got := range map[string]*gateonv1.GlobalConfig{"live": reg.Get(context.Background()), "persisted": persisted} {
		assertSectionsKept(t, name, got)
		if !slices.Equal(got.GetWaf().GetOrigins(), []string{"example.com", "api.example.com"}) {
			t.Errorf("%s: waf.origins = %v; the section that was sent was not applied", name, got.GetWaf().GetOrigins())
		}
	}
}

func assertSectionsKept(t *testing.T, name string, got *gateonv1.GlobalConfig) {
	t.Helper()
	want := storedGlobalConfig()
	if got.GetAuth().GetPasetoSecret() != want.Auth.PasetoSecret {
		t.Errorf("%s: auth.paseto_secret = %q; an update that did not mention auth erased it", name, got.GetAuth().GetPasetoSecret())
	}
	if got.GetAuth().GetDatabaseConfig().GetHost() != "db.internal" {
		t.Errorf("%s: auth.database_config = %v; the next start falls back to a fresh SQLite file with no administrator",
			name, got.GetAuth().GetDatabaseConfig())
	}
	if !slices.Equal(got.GetManagement().GetAllowedIps(), want.Management.AllowedIps) {
		t.Errorf("%s: management.allowed_ips = %v; the next start restores the default, which admits every address",
			name, got.GetManagement().GetAllowedIps())
	}
	if len(got.GetTls().GetCertificates()) != 1 {
		t.Errorf("%s: %d certificates left, want the 1 that was stored", name, len(got.GetTls().GetCertificates()))
	}
	if got.GetProfile() != want.Profile {
		t.Errorf("%s: profile = %q, want %q kept", name, got.GetProfile(), want.Profile)
	}
}
