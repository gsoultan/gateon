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

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/config/storedsecret"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// globalsAPI serves one registry, and saves through the API's own path.
type globalsAPI struct {
	GlobalAndAuthAPI
	store config.GlobalConfigStore
}

func (g *globalsAPI) GetGlobals() config.GlobalConfigStore { return g.store }

// UpdateGlobalConfig is the API's own: PUT /v1/global stores and applies a
// save through it, and the tests using this fake are about what that stores.
func (g *globalsAPI) UpdateGlobalConfig(ctx context.Context, req *gateonv1.UpdateGlobalConfigRequest) (*gateonv1.UpdateGlobalConfigResponse, error) {
	return (&api.ApiService{Globals: g.store}).UpdateGlobalConfig(ctx, req)
}

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

// TestGlobalConfigReadGivesAWriterThePlaceholder: a role that may write the
// config reads each stored credential as the placeholder, which a save sends
// back to keep it -- never the value. It used to read every value, so one
// stolen administrator session carried off the session-signing key.
func TestGlobalConfigReadGivesAWriterThePlaceholder(t *testing.T) {
	mux := globalMuxWithSecrets(t)
	for _, role := range []string{auth.RoleAdmin, auth.RoleOperator} {
		body := getGlobalAs(t, mux, role).Body.String()
		for _, secret := range restGlobalCredentials {
			if strings.Contains(body, secret) {
				t.Errorf("%s received the stored credential %q from GET /v1/global", role, secret)
			}
		}
		var got gateonv1.GlobalConfig
		if err := ProtojsonUnmarshalOptions().Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
		if got.GetAuth().GetPasetoSecret() != storedsecret.Sentinel || got.GetRedis().GetPassword() != storedsecret.Sentinel {
			t.Errorf("%s reads the session key as %q and the Redis password as %q; want the placeholder for both",
				role, got.GetAuth().GetPasetoSecret(), got.GetRedis().GetPassword())
		}
	}
}

// TestGlobalConfigSaveRefusesAPlaceholderItCannotKeep: a dispatcher that asks
// to keep a stored secret under an id no stored dispatcher has is refused with
// 400 and its name, and nothing is stored.
func TestGlobalConfigSaveRefusesAPlaceholderItCannotKeep(t *testing.T) {
	mux := globalMuxWithSecrets(t)
	body := `{"alerting": {"dispatchers": [{"id": "d-unknown", "name": "pager", "type": "telegram", "telegramBotToken": "` +
		storedsecret.Sentinel + `"}]}}`
	req := httptest.NewRequest(http.MethodPut, "/v1/global", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "u-admin", Username: "admin", Role: auth.RoleAdmin}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `id \"d-unknown\", name \"pager\"`) {
		t.Fatalf("PUT answered %d %s; want 400 naming the dispatcher", rr.Code, rr.Body)
	}
	after := getGlobalAs(t, mux, auth.RoleAdmin).Body.String()
	if strings.Contains(after, "d-unknown") {
		t.Fatal("the refused save was stored")
	}
}
