// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// globalCredentials are the values a viewer must never receive. Each one is
// stored in secretLadenGlobalConfig under the field it belongs to.
var globalCredentials = []string{
	"PASETO-KEY-32-BYTES-LONG-SECRET!",
	"db-pass",
	"AUDIT-HMAC-KEY",
	"redis-pass",
	"vrrp-pass",
	"MAXMIND-KEY",
	"GITOPS-TOKEN",
	"BOT-SECRET",
	"CANARY-TOKEN",
	"POW-SECRET",
	"ABUSEIPDB-KEY",
	"TG-TOKEN",
	"hooks.slack.com/services/T/B/SECRET",
}

func secretLadenGlobalConfig() *gateonv1.GlobalConfig {
	return &gateonv1.GlobalConfig{
		Auth: &gateonv1.AuthConfig{
			Enabled:      true,
			PasetoSecret: "PASETO-KEY-32-BYTES-LONG-SECRET!",
			DatabaseUrl:  "postgres://gateon:db-pass@db/gateon",
		},
		Audit:      &gateonv1.AuditConfig{SignEntries: true, SignatureKey: "AUDIT-HMAC-KEY"},
		Redis:      &gateonv1.RedisConfig{Addr: "redis:6379", Password: "redis-pass"},
		Ha:         &gateonv1.HaConfig{AuthPass: "vrrp-pass"},
		Geoip:      &gateonv1.GeoIPConfig{MaxmindLicenseKey: "MAXMIND-KEY"},
		Management: &gateonv1.ManagementConfig{Gitops: &gateonv1.GitOpsConfig{AuthToken: "GITOPS-TOKEN"}},
		Waf:        &gateonv1.WafConfig{BotManagement: &gateonv1.BotManagementConfig{SecretKey: "BOT-SECRET"}},
		SecurityAdvanced: &gateonv1.SecurityAdvancedConfig{
			Deception: &gateonv1.DeceptionConfig{CanaryToken: "CANARY-TOKEN"},
			Pow:       &gateonv1.PowConfig{Secret: "POW-SECRET"},
			IpReputation: &gateonv1.IPReputationConfig{
				Integrations: []*gateonv1.IPReputationIntegration{{Type: "abuseipdb", ApiKey: "ABUSEIPDB-KEY"}},
			},
		},
		Alerting: &gateonv1.AlertingConfig{Dispatchers: []*gateonv1.AlertDispatcher{{
			Type:             "telegram",
			TelegramBotToken: "TG-TOKEN",
			WebhookUrl:       "https://hooks.slack.com/services/T/B/SECRET",
		}}},
	}
}

func globalRegistryWithSecrets(t *testing.T) *config.GlobalRegistry {
	t.Helper()
	reg := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	if err := reg.Update(context.Background(), secretLadenGlobalConfig()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	return reg
}

func withRole(role string) context.Context {
	return context.WithValue(context.Background(), middleware.UserContextKey,
		&auth.Claims{ID: "u-" + role, Username: role, Role: role})
}

// TestGetGlobalConfigWithholdsCredentialsFromAViewer is the question stated as
// a test: RoleViewer holds ActionRead on ResourceGlobal so the dashboard can
// render settings. Does that read hand the lowest role the PASETO session
// key, the audit chain's signing key and every stored password and token?
func TestGetGlobalConfigWithholdsCredentialsFromAViewer(t *testing.T) {
	reg := globalRegistryWithSecrets(t)
	svc := &ApiService{Globals: reg}

	resp, err := svc.GetGlobalConfig(withRole(auth.RoleViewer), &gateonv1.GetGlobalConfigRequest{})
	if err != nil {
		t.Fatalf("GetGlobalConfig: %v", err)
	}
	got := protojson.Format(resp.Config)
	for _, secret := range globalCredentials {
		if strings.Contains(got, secret) {
			t.Errorf("a viewer received credential %q from GetGlobalConfig", secret)
		}
	}

	// Redaction must be on a copy: the registry hands out its live pointer,
	// and blanking that would erase the secrets from the running gateway.
	live := protojson.Format(reg.Get(context.Background()))
	for _, secret := range globalCredentials {
		if !strings.Contains(live, secret) {
			t.Errorf("credential %q was erased from the live config by a read", secret)
		}
	}
}

// TestGetGlobalConfigRoundTripsCredentialsForAWriter pins the other half: the
// settings editor sends the whole config back on save, so a role that can
// write it must still receive every value.
func TestGetGlobalConfigRoundTripsCredentialsForAWriter(t *testing.T) {
	svc := &ApiService{Globals: globalRegistryWithSecrets(t)}
	for _, role := range []string{auth.RoleAdmin, auth.RoleOperator} {
		resp, err := svc.GetGlobalConfig(withRole(role), &gateonv1.GetGlobalConfigRequest{})
		if err != nil {
			t.Fatalf("GetGlobalConfig(%s): %v", role, err)
		}
		got := protojson.Format(resp.Config)
		for _, secret := range globalCredentials {
			if !strings.Contains(got, secret) {
				t.Errorf("%s no longer receives %q, so saving settings would blank it", role, secret)
			}
		}
	}
}
