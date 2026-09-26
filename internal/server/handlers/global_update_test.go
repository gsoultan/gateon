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

// updatingGlobalsAPI records what reaches UpdateGlobalConfig, which is where
// the API applies a settings change.
type updatingGlobalsAPI struct {
	GlobalAndAuthAPI
	store   config.GlobalConfigStore
	applied []*gateonv1.GlobalConfig
}

func (a *updatingGlobalsAPI) GetGlobals() config.GlobalConfigStore { return a.store }

func (a *updatingGlobalsAPI) UpdateGlobalConfig(ctx context.Context, req *gateonv1.UpdateGlobalConfigRequest) (*gateonv1.UpdateGlobalConfigResponse, error) {
	a.applied = append(a.applied, req.Config)
	if err := a.store.Update(ctx, req.Config); err != nil {
		return &gateonv1.UpdateGlobalConfigResponse{}, err
	}
	return &gateonv1.UpdateGlobalConfigResponse{Success: true}, nil
}

// The dashboard saves settings over PUT /v1/global. That handler stored the
// body and applied a handful of things itself, while the API's
// UpdateGlobalConfig is where a change is applied: TLS (the ACME switch,
// certificates and client authorities), alerting, IP reputation, retention,
// eBPF port knocking, a generated audit signing key. None of those reached a
// save made from the dashboard until the gateway restarted.
func TestSavingSettingsFromTheDashboardAppliesThem(t *testing.T) {
	api := &updatingGlobalsAPI{store: config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, api, &Deps{})

	req := httptest.NewRequest(http.MethodPut, "/v1/global",
		strings.NewReader(`{"tls":{"enabled":true,"acme":{"enabled":true}}}`))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "u-admin", Username: "admin", Role: auth.RoleAdmin}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /v1/global answered %d: %s", rec.Code, rec.Body.String())
	}
	if len(api.applied) != 1 || !api.applied[0].GetTls().GetAcme().GetEnabled() {
		t.Fatalf("the saved settings were not applied through UpdateGlobalConfig (applied %d times)", len(api.applied))
	}
}
