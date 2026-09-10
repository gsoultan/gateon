// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// POST /v1/setup/test-db opens a database connection to a DSN the caller
// supplies, and is meant to be reachable only while the gateway is unconfigured.
// The guard read:
//
//	setupReq, err := svc.IsSetupRequired(...)
//	if err == nil && !setupReq.Required { deny }
//
// so an error meant "not denied" and execution fell through to db.Open with the
// caller's DSN. IsSetupRequired returns a nil error on every path today, which
// is what makes this latent rather than live — and is exactly how the two
// fail-open defects already found in this codebase read before something on
// their path started returning errors.
//
// The err case is only testable because the setup state is injected here; the
// production implementation cannot currently produce it.

type setupStateAPI struct {
	GlobalAndAuthAPI
	required bool
	err      error
}

func (s *setupStateAPI) IsSetupRequired(_ context.Context, _ *gateonv1.IsSetupRequiredRequest) (*gateonv1.IsSetupRequiredResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &gateonv1.IsSetupRequiredResponse{Required: s.required}, nil
}

func postTestDB(t *testing.T, svc GlobalAndAuthAPI, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, svc, &Deps{})
	req := httptest.NewRequest(http.MethodPost, "/v1/setup/test-db", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestSetupTestDBRefusedOnceSetupIsComplete(t *testing.T) {
	rr := postTestDB(t, &setupStateAPI{required: false}, `{"database_url":"postgres://x/y"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 once setup is complete", rr.Code)
	}
}

// The fail-closed half. An unknown setup state must deny, because the thing
// behind the guard makes an outbound connection to an address the caller chose
// and returns the connection error verbatim — a usable port-scan oracle.
func TestSetupTestDBRefusedWhenSetupStateIsUnknown(t *testing.T) {
	rr := postTestDB(t, &setupStateAPI{err: errors.New("database unreachable")},
		`{"database_url":"postgres://internal-host:5432/x"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 when the setup state cannot be determined; "+
			"an error must not read as permission to open a caller-supplied DSN", rr.Code)
	}
}

// And the guard must still let the wizard through, or the fix for the
// reachability bug would be undone by an over-tight guard.
func TestSetupTestDBReachesTheHandlerDuringSetup(t *testing.T) {
	rr := postTestDB(t, &setupStateAPI{required: true}, `not json`)
	if rr.Code == http.StatusForbidden {
		t.Fatal("status = 403 while setup is required; the wizard's connection test must run")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for malformed json once past the guard", rr.Code)
	}
}
