// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
)

// triggerWafUpdateProcedure is the Connect path the removed RPC answered on,
// spelled out because its generated constant is gone with it.
const triggerWafUpdateProcedure = "/" + gateonv1connect.ApiServiceName + "/TriggerWafUpdate"

// TestTheTriggerWafUpdateRPCIsGone: the RPC could only fail -- there is no
// rule source to update from -- and is removed with its REST route (ADR
// 0064). No permission entry may remain for it, and a call over Connect is
// answered as an unknown procedure (404), by an authorization interceptor that
// therefore never sees it.
func TestTheTriggerWafUpdateRPCIsGone(t *testing.T) {
	for procedure := range apiPermissions {
		if strings.Contains(procedure, "TriggerWafUpdate") {
			t.Errorf("apiPermissions still has an entry for %s", procedure)
		}
	}

	path, h := gateonv1connect.NewApiServiceHandler(&spyApiService{})
	mux := http.NewServeMux()
	mux.Handle(path, h)
	req := httptest.NewRequest(http.MethodPost, triggerWafUpdateProcedure, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST %s = %d, want 404 (no such procedure): %s", triggerWafUpdateProcedure, rec.Code, rec.Body.String())
	}
}
