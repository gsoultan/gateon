// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func publicManagementService(t *testing.T) *ApiService {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	reg := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	if err := reg.Update(context.Background(), &gateonv1.GlobalConfig{
		Auth:       &gateonv1.AuthConfig{Enabled: true, PasetoSecret: "0123456789abcdef0123456789abcdef"},
		Management: &gateonv1.ManagementConfig{AllowPublicManagement: true},
	}); err != nil {
		t.Fatal(err)
	}
	return &ApiService{Globals: reg}
}

func as(role string) context.Context {
	return context.WithValue(context.Background(), middleware.UserContextKey,
		&auth.Claims{ID: role + "-1", Username: role, Role: role})
}

// TestARecommendationIsHeldToTheSameBoundaryAsASave: the fixed-purpose
// writers store the global configuration without going through
// UpdateGlobalConfig. The one that changes management exposure is
// administrator-only like any other save of it; one that changes an
// operational setting is not.
func TestARecommendationIsHeldToTheSameBoundaryAsASave(t *testing.T) {
	t.Run("operator may not change management exposure", func(t *testing.T) {
		s := publicManagementService(t)
		resp, err := s.ApplyRecommendation(as(auth.RoleOperator),
			&gateonv1.ApplyRecommendationRequest{AnomalyType: "management_access_violation"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetSuccess() || !strings.Contains(resp.GetMessage(), "management.allow_public_management") {
			t.Fatalf("an operator's recommendation changed management exposure: %+v", resp)
		}
		if !s.Globals.Get(context.Background()).GetManagement().GetAllowPublicManagement() {
			t.Fatal("the refused recommendation was applied anyway")
		}
	})
	t.Run("administrator may", func(t *testing.T) {
		s := publicManagementService(t)
		resp, err := s.ApplyRecommendation(as(auth.RoleAdmin),
			&gateonv1.ApplyRecommendationRequest{AnomalyType: "management_access_violation"})
		if err != nil || !resp.GetSuccess() {
			t.Fatalf("an administrator's recommendation: %+v %v", resp, err)
		}
		if s.Globals.Get(context.Background()).GetManagement().GetAllowPublicManagement() {
			t.Fatal("the administrator's recommendation was not applied")
		}
	})
	t.Run("operator may block a country, without editing the live config in place", func(t *testing.T) {
		s := publicManagementService(t)
		before := s.Globals.Get(context.Background())
		resp, err := s.ApplyRecommendation(as(auth.RoleOperator),
			&gateonv1.ApplyRecommendationRequest{AnomalyType: "geofence_violation", Source: "XX"})
		if err != nil || !resp.GetSuccess() {
			t.Fatalf("an operator blocking a country: %+v %v", resp, err)
		}
		if !slices.Contains(s.Globals.Get(context.Background()).GetGeoip().GetBlockedCountries(), "XX") {
			t.Fatal("the country was not blocked")
		}
		if before.GetGeoip() != nil {
			t.Fatal("the recommendation edited the configuration it read in place, rather than a copy")
		}
	})
}
