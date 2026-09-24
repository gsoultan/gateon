// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestUpdateGlobalConfigKeepsTheSectionsItWasNotSent is the Connect and gRPC
// twin of the REST test of the same name: both transports stored the request
// as the whole configuration, so a request carrying one section deleted the
// others -- the auth database and session key, the management allowlist, the
// certificates -- and the next start rebuilt them from defaults.
func TestUpdateGlobalConfigKeepsTheSectionsItWasNotSent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "global.json")
	reg := config.NewGlobalRegistry(path)
	stored := &gateonv1.GlobalConfig{
		Auth:       &gateonv1.AuthConfig{Enabled: true, PasetoSecret: "PASETO-KEY-32-BYTES-LONG-SECRET!", DatabaseUrl: "postgres://gateon:db-pass@db/gateon"},
		Management: &gateonv1.ManagementConfig{Bind: "10.0.0.5", Port: "9443", AllowedIps: []string{"10.0.0.0/8"}},
		Tls:        &gateonv1.TlsConfig{Certificates: []*gateonv1.Certificate{{Id: "prod-cert"}}},
		Profile:    "minimal",
	}
	if err := reg.Update(context.Background(), stored); err != nil {
		t.Fatalf("seeding the stored config: %v", err)
	}
	s := &ApiService{Globals: reg}

	resp, err := s.UpdateGlobalConfig(context.Background(), &gateonv1.UpdateGlobalConfigRequest{
		Config: &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, Origins: []string{"example.com"}}},
	})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("UpdateGlobalConfig = %v, %v", resp, err)
	}

	for name, got := range map[string]*gateonv1.GlobalConfig{
		"live":      reg.Get(context.Background()),
		"persisted": config.NewGlobalRegistry(path).Get(context.Background()),
	} {
		if got.GetAuth().GetPasetoSecret() != "PASETO-KEY-32-BYTES-LONG-SECRET!" || got.GetAuth().GetDatabaseUrl() == "" {
			t.Errorf("%s: auth = %v; an update that did not mention auth erased it", name, got.GetAuth())
		}
		if !slices.Equal(got.GetManagement().GetAllowedIps(), []string{"10.0.0.0/8"}) {
			t.Errorf("%s: management.allowed_ips = %v, want the stored allowlist kept", name, got.GetManagement().GetAllowedIps())
		}
		if len(got.GetTls().GetCertificates()) != 1 {
			t.Errorf("%s: %d certificates, want the 1 stored", name, len(got.GetTls().GetCertificates()))
		}
		if got.GetProfile() != "minimal" {
			t.Errorf("%s: profile = %q, want \"minimal\" kept", name, got.GetProfile())
		}
		if !slices.Equal(got.GetWaf().GetOrigins(), []string{"example.com"}) {
			t.Errorf("%s: waf.origins = %v; the section that was sent was not applied", name, got.GetWaf().GetOrigins())
		}
	}
}

// TestKeepOmittedSectionsHonoursASectionThatWasSent pins the other half: a
// section present in the update replaces the stored one outright, even when
// it is empty, and the carried sections are copies rather than the stored
// messages themselves.
func TestKeepOmittedSectionsHonoursASectionThatWasSent(t *testing.T) {
	stored := &gateonv1.GlobalConfig{
		Redis: &gateonv1.RedisConfig{Enabled: true, Addr: "redis:6379"},
		Otel:  &gateonv1.OtelConfig{Enabled: true, Endpoint: "otel:4317"},
	}
	update := &gateonv1.GlobalConfig{Redis: &gateonv1.RedisConfig{}, Profile: "enterprise"}

	KeepOmittedSections(update, stored)

	if update.GetRedis().GetEnabled() || update.GetRedis().GetAddr() != "" {
		t.Errorf("redis = %v; a section that was sent, even empty, must replace the stored one", update.GetRedis())
	}
	if update.GetProfile() != "enterprise" {
		t.Errorf("profile = %q; a profile that was sent must win", update.GetProfile())
	}
	if update.GetOtel().GetEndpoint() != "otel:4317" {
		t.Fatalf("otel = %v; the omitted section was not carried", update.GetOtel())
	}
	update.Otel.Endpoint = "changed"
	if stored.Otel.Endpoint != "otel:4317" {
		t.Error("the carried section aliases the stored one; editing the update rewrote the live config")
	}
}
