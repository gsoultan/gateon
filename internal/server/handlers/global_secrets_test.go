// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// globalsAPI serves one registry and nothing else.
type globalsAPI struct {
	GlobalAndAuthAPI
	store config.GlobalConfigStore
}

func (g *globalsAPI) GetGlobals() config.GlobalConfigStore { return g.store }

var restGlobalCredentials = []string{"PASETO-KEY-32-BYTES-LONG-SECRET!", "AUDIT-HMAC-KEY", "redis-pass", "TG-TOKEN"}

func globalMuxWithSecrets(t *testing.T) *http.ServeMux {
	t.Helper()
	reg := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	err := reg.Update(context.Background(), &gateonv1.GlobalConfig{
		Auth:     &gateonv1.AuthConfig{Enabled: true, PasetoSecret: "PASETO-KEY-32-BYTES-LONG-SECRET!"},
		Audit:    &gateonv1.AuditConfig{SignEntries: true, SignatureKey: "AUDIT-HMAC-KEY"},
		Redis:    &gateonv1.RedisConfig{Addr: "redis:6379", Password: "redis-pass"},
		Alerting: &gateonv1.AlertingConfig{Dispatchers: []*gateonv1.AlertDispatcher{{Type: "telegram", TelegramBotToken: "TG-TOKEN"}}},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, &globalsAPI{store: reg}, &Deps{})
	return mux
}

func getGlobalAs(t *testing.T, mux *http.ServeMux, role string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/global", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "u-" + role, Username: role, Role: role}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/global as %s: status %d: %s", role, rr.Code, rr.Body.String())
	}
	return rr
}

// TestGlobalConfigReadWithholdsCredentialsFromAViewer is the REST twin of the
// ApiService test: the dashboard reads settings over GET /v1/global, and
// RoleViewer is admitted to it.
func TestGlobalConfigReadWithholdsCredentialsFromAViewer(t *testing.T) {
	mux := globalMuxWithSecrets(t)
	body := getGlobalAs(t, mux, auth.RoleViewer).Body.String()
	for _, secret := range restGlobalCredentials {
		if strings.Contains(body, secret) {
			t.Errorf("a viewer received credential %q from GET /v1/global", secret)
		}
	}
}

func TestGlobalConfigReadRoundTripsCredentialsForAWriter(t *testing.T) {
	mux := globalMuxWithSecrets(t)
	for _, role := range []string{auth.RoleAdmin, auth.RoleOperator} {
		body := getGlobalAs(t, mux, role).Body.String()
		for _, secret := range restGlobalCredentials {
			if !strings.Contains(body, secret) {
				t.Errorf("%s no longer receives %q from GET /v1/global; saving settings would blank it", role, secret)
			}
		}
	}
}
