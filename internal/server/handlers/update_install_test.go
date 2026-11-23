// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// installRPC answers InstallUpdate and records what reached it. Who may
// install is the service's rule and is tested in internal/api; these tests
// hold the REST transport to the RPC and to its answers.
type installRPC struct {
	updateRPCs
	asked []string
	// rolled is what RollbackUpdate was asked for.
	rolled []string
	err    error
}

func (i *installRPC) InstallUpdate(_ context.Context, req *gateonv1.InstallUpdateRequest) (*gateonv1.InstallUpdateResponse, error) {
	i.asked = append(i.asked, req.GetVersion())
	if i.err != nil {
		return nil, i.err
	}
	st := newerStatus()
	st.Upgrade = &gateonv1.UpgradeStatus{Current: &gateonv1.UpgradeRecord{
		Phase: gateonv1.UpgradePhase_UPGRADE_PHASE_DOWNLOADING, TargetVersion: req.GetVersion(),
	}}
	return &gateonv1.InstallUpdateResponse{Status: st}, nil
}

func (i *installRPC) RollbackUpdate(_ context.Context, req *gateonv1.RollbackUpdateRequest) (*gateonv1.RollbackUpdateResponse, error) {
	i.rolled = append(i.rolled, req.GetVersion())
	if i.err != nil {
		return nil, i.err
	}
	st := newerStatus()
	st.Upgrade = &gateonv1.UpgradeStatus{Current: &gateonv1.UpgradeRecord{
		Phase: gateonv1.UpgradePhase_UPGRADE_PHASE_REQUESTED, Reason: gateonv1.UpgradeReason_UPGRADE_REASON_REQUESTED,
		PreviousVersion: req.GetVersion(),
	}}
	return &gateonv1.RollbackUpdateResponse{Status: st}, nil
}

func installRequest(t *testing.T, svc GlobalAndAuthAPI, role, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	return updatePost(t, svc, "/v1/update/install", role, method, body)
}

func updatePost(t *testing.T, svc GlobalAndAuthAPI, path, role, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerUpdateHandlers(mux, svc)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "u-" + role, Username: role, Role: role}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

const installBody = `{"version":"1.8.3"}`

// TestInstallUpdateRESTServesTheRPC: the dashboard's button and a script
// with curl start the same install the gRPC call does, naming the version.
func TestInstallUpdateRESTServesTheRPC(t *testing.T) {
	svc := &installRPC{}
	rr := installRequest(t, svc, auth.RoleAdmin, http.MethodPost, installBody)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status %d, want 202 (started, not finished): %s", rr.Code, rr.Body)
	}
	if len(svc.asked) != 1 || svc.asked[0] != "1.8.3" {
		t.Fatalf("the RPC was asked for %v, want the version in the body", svc.asked)
	}
	if body := rr.Body.String(); !strings.Contains(body, `"targetVersion":"1.8.3"`) || !strings.Contains(body, `"latestVersion":"1.8.3"`) {
		t.Errorf("the answer does not carry the install: %s", body)
	}
}

func TestInstallUpdateRESTIsRefusedBeforeTheRPCForAViewer(t *testing.T) {
	svc := &installRPC{}
	if rr := installRequest(t, svc, auth.RoleViewer, http.MethodPost, installBody); rr.Code != http.StatusForbidden {
		t.Errorf("viewer: status %d, want 403", rr.Code)
	}
	// An install is a POST: a link, an image tag or a prefetch must not start one.
	if rr := installRequest(t, svc, auth.RoleAdmin, http.MethodGet, ""); rr.Code == http.StatusAccepted || rr.Code == http.StatusOK {
		t.Errorf("GET started an install: %d", rr.Code)
	}
	if rr := installRequest(t, svc, auth.RoleAdmin, http.MethodPost, `{"version":`); rr.Code != http.StatusBadRequest {
		t.Errorf("a body that is not JSON: status %d, want 400", rr.Code)
	}
	if len(svc.asked) != 0 {
		t.Fatalf("a refused request reached the installer: %v", svc.asked)
	}
}

// TestInstallUpdateRESTAnswersARefusalWithItsReason: an operator the
// service turns away must see 403 and not 500, and a refusal must never
// read as "started".
func TestInstallUpdateRESTAnswersARefusalWithItsReason(t *testing.T) {
	cases := []struct {
		err  error
		code int
		says string
	}{
		{status.Error(codes.PermissionDenied, "only an administrator installs a release"), http.StatusForbidden, "only an administrator"},
		{status.Error(codes.Aborted, "an install is already running"), http.StatusConflict, "already running"},
		{status.Error(codes.FailedPrecondition, "this gateway cannot install releases"), http.StatusConflict, "cannot install"},
		{status.Error(codes.Internal, "open /var/lib/gateon/upgrade: disk on fire"), http.StatusInternalServerError, "could not be started"},
	}
	for _, c := range cases {
		rr := installRequest(t, &installRPC{err: c.err}, auth.RoleOperator, http.MethodPost, installBody)
		if rr.Code != c.code || !strings.Contains(rr.Body.String(), c.says) {
			t.Errorf("%v: answered %d %s, want %d saying %q", c.err, rr.Code, rr.Body, c.code, c.says)
		}
		if strings.Contains(rr.Body.String(), "/var/lib") {
			t.Errorf("an internal failure reached the caller verbatim: %s", rr.Body)
		}
	}
}

const (
	rollbackPath = "/v1/update/rollback"
	rollbackBody = `{"version":"1.8.1"}`
)

// TestRollbackUpdateRESTServesTheRPC: the dashboard's button reaches the
// same rollback the gRPC call does, naming the release it was shown.
func TestRollbackUpdateRESTServesTheRPC(t *testing.T) {
	svc := &installRPC{}
	rr := updatePost(t, svc, rollbackPath, auth.RoleAdmin, http.MethodPost, rollbackBody)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status %d, want 202 (started, not finished): %s", rr.Code, rr.Body)
	}
	if len(svc.rolled) != 1 || svc.rolled[0] != "1.8.1" || len(svc.asked) != 0 {
		t.Fatalf("rollbacks %v and installs %v, want one rollback to the version in the body", svc.rolled, svc.asked)
	}
	if body := rr.Body.String(); !strings.Contains(body, `"previousVersion":"1.8.1"`) {
		t.Errorf("the answer does not carry the rollback: %s", body)
	}
}

func TestRollbackUpdateRESTIsRefusedBeforeTheRPC(t *testing.T) {
	svc := &installRPC{}
	if rr := updatePost(t, svc, rollbackPath, auth.RoleViewer, http.MethodPost, rollbackBody); rr.Code != http.StatusForbidden {
		t.Errorf("viewer: status %d, want 403", rr.Code)
	}
	if rr := updatePost(t, svc, rollbackPath, auth.RoleAdmin, http.MethodGet, ""); rr.Code == http.StatusAccepted || rr.Code == http.StatusOK {
		t.Errorf("GET started a rollback: %d", rr.Code)
	}
	if rr := updatePost(t, svc, rollbackPath, auth.RoleAdmin, http.MethodPost, `{"version":`); rr.Code != http.StatusBadRequest {
		t.Errorf("a body that is not JSON: status %d, want 400", rr.Code)
	}
	if len(svc.rolled) != 0 {
		t.Fatalf("a refused request reached the installer: %v", svc.rolled)
	}
	// The service's own refusal of an operator is answered as one.
	denied := &installRPC{err: status.Error(codes.PermissionDenied, "only an administrator rolls a release back")}
	if rr := updatePost(t, denied, rollbackPath, auth.RoleOperator, http.MethodPost, rollbackBody); rr.Code != http.StatusForbidden {
		t.Errorf("an operator the service refused: status %d, want 403", rr.Code)
	}
	needs := &installRPC{err: status.Error(codes.FailedPrecondition, "rolling back needs the database copy put back")}
	rr := updatePost(t, needs, rollbackPath, auth.RoleAdmin, http.MethodPost, rollbackBody)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "database copy") {
		t.Errorf("a rollback that needs a restore: %d %s", rr.Code, rr.Body)
	}
}
