// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// updateRPCs answers the two release-check RPCs and counts what reaches
// them. The check itself is tested in internal/selfupdate; these tests hold
// the REST transport to the RPCs and to their permissions.
type updateRPCs struct {
	GlobalAndAuthAPI
	reads, checks int
}

func newerStatus() *gateonv1.UpdateStatus {
	return &gateonv1.UpdateStatus{
		CurrentVersion: "1.8.2", LatestVersion: "1.8.3", UpdateAvailable: true,
		State:       gateonv1.UpdateCheckState_UPDATE_CHECK_STATE_OK,
		Signature:   gateonv1.UpdateSignature_UPDATE_SIGNATURE_VERIFIED,
		InstallKind: gateonv1.InstallKind_INSTALL_KIND_SYSTEMD,
	}
}

func (u *updateRPCs) GetUpdateStatus(context.Context, *gateonv1.GetUpdateStatusRequest) (*gateonv1.GetUpdateStatusResponse, error) {
	u.reads++
	return &gateonv1.GetUpdateStatusResponse{Status: newerStatus()}, nil
}

func (u *updateRPCs) CheckForUpdate(context.Context, *gateonv1.CheckForUpdateRequest) (*gateonv1.CheckForUpdateResponse, error) {
	u.checks++
	return &gateonv1.CheckForUpdateResponse{Status: newerStatus()}, nil
}

func updateRequest(t *testing.T, svc GlobalAndAuthAPI, role, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerUpdateHandlers(mux, svc)
	req := httptest.NewRequest(method, path, http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "u-" + role, Username: role, Role: role}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestUpdateStatusRESTServesTheRPC: every role that can open the dashboard
// reads the status its header notice is drawn from, and reading it never
// starts a check.
func TestUpdateStatusRESTServesTheRPC(t *testing.T) {
	svc := &updateRPCs{}
	for _, role := range []string{auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin} {
		rr := updateRequest(t, svc, role, http.MethodGet, "/v1/update/status")
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", role, rr.Code, rr.Body)
		}
		if body["latestVersion"] != "1.8.3" || body["updateAvailable"] != true || body["currentVersion"] != "1.8.2" {
			t.Errorf("%s: body = %s", role, rr.Body)
		}
	}
	if svc.reads != 3 || svc.checks != 0 {
		t.Errorf("reads %d, checks %d; want 3 reads and no check", svc.reads, svc.checks)
	}
}

// TestCheckForUpdateRESTNeedsTheRightToChangeSettings: a check makes the
// gateway call out, which a viewer may not cause.
func TestCheckForUpdateRESTNeedsTheRightToChangeSettings(t *testing.T) {
	svc := &updateRPCs{}
	if rr := updateRequest(t, svc, auth.RoleViewer, http.MethodPost, "/v1/update/check"); rr.Code != http.StatusForbidden {
		t.Errorf("viewer: status %d, want 403", rr.Code)
	}
	if svc.checks != 0 {
		t.Fatal("a refused check still reached the checker")
	}
	for _, role := range []string{auth.RoleOperator, auth.RoleAdmin} {
		if rr := updateRequest(t, svc, role, http.MethodPost, "/v1/update/check"); rr.Code != http.StatusOK {
			t.Errorf("%s: %d %s", role, rr.Code, rr.Body)
		}
	}
	if svc.checks != 2 {
		t.Errorf("checks = %d, want 2", svc.checks)
	}
	// A check is a POST: a link, an image tag or a prefetch must not start one.
	if rr := updateRequest(t, svc, auth.RoleAdmin, http.MethodGet, "/v1/update/check"); rr.Code == http.StatusOK || svc.checks != 2 {
		t.Errorf("GET /v1/update/check: status %d, checks %d", rr.Code, svc.checks)
	}
}
