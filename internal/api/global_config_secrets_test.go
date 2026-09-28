// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/config/storedsecret"
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

// TestGetGlobalConfigGivesAWriterNoCredential pins the other half: a role that
// may write the config reads each credential as the placeholder, and a save of
// what it read, unchanged, keeps every stored credential. It used to read every
// value -- the settings editor sends the config back on save -- so a stolen
// administrator session, or script in the dashboard, carried them all off.
func TestGetGlobalConfigGivesAWriterNoCredential(t *testing.T) {
	reg := globalRegistryWithSecrets(t)
	svc := &ApiService{Globals: reg}
	before := protojson.Format(reg.Get(context.Background()))
	for _, role := range []string{auth.RoleAdmin, auth.RoleOperator} {
		resp, err := svc.GetGlobalConfig(withRole(role), &gateonv1.GetGlobalConfigRequest{})
		if err != nil {
			t.Fatalf("GetGlobalConfig(%s): %v", role, err)
		}
		got := protojson.Format(resp.Config)
		for _, secret := range globalCredentials {
			if strings.Contains(got, secret) {
				t.Errorf("%s received the stored credential %q", role, secret)
			}
		}
		if _, err := svc.UpdateGlobalConfig(withRole(role), &gateonv1.UpdateGlobalConfigRequest{Config: resp.Config}); err != nil {
			t.Fatalf("saving what %s read, unchanged: %v", role, err)
		}
		if after := protojson.Format(reg.Get(context.Background())); after != before {
			t.Fatalf("saving what %s read, unchanged, changed the stored config:\n got %s\nwant %s", role, after, before)
		}
	}
}

// TestUpdateGlobalConfigRefusesAPlaceholderItCannotKeep: the refusal is
// InvalidArgument, names the element, and stores nothing.
func TestUpdateGlobalConfigRefusesAPlaceholderItCannotKeep(t *testing.T) {
	reg := globalRegistryWithSecrets(t)
	svc := &ApiService{Globals: reg}
	before := protojson.Format(reg.Get(context.Background()))
	update := &gateonv1.GlobalConfig{Redis: &gateonv1.RedisConfig{Addr: "attacker.example:6379", Password: storedsecret.Sentinel}}
	_, err := svc.UpdateGlobalConfig(withRole(auth.RoleAdmin), &gateonv1.UpdateGlobalConfigRequest{Config: update})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "redis.password") {
		t.Fatalf("UpdateGlobalConfig = %v; want InvalidArgument naming redis.password", err)
	}
	if after := protojson.Format(reg.Get(context.Background())); after != before {
		t.Fatal("a refused update changed the stored config")
	}
}
