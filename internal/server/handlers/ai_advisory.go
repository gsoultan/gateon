// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// registerAIAdvisoryHandlers wires the Security Hub "AI Advisory" and the Log
// Assistant to the ApiService RPCs that Connect and gRPC serve too, so all
// three transports return the same analysis (ADR 0070). The analysis lives in
// internal/ai/advisory.
func registerAIAdvisoryHandlers(mux *http.ServeMux, svc GlobalAndAuthAPI) {
	mux.HandleFunc("POST /v1/AnalyzeConfig", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		var req gateonv1.AnalyzeConfigRequest
		if !DecodeProtoRequest(w, r, &req) {
			return
		}
		res, err := svc.AnalyzeConfig(r.Context(), &req)
		writeAIResponse(w, res, err)
	})

	mux.HandleFunc("POST /v1/AnalyzeLogs", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		var req gateonv1.AnalyzeLogsRequest
		if !DecodeProtoRequest(w, r, &req) {
			return
		}
		res, err := svc.AnalyzeLogs(r.Context(), &req)
		writeAIResponse(w, res, err)
	})

	// The test spends a call against the stored key, so it takes the right to
	// change the settings it tests, not merely to read diagnostics.
	mux.HandleFunc("POST /v1/ai-advisory/test", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		res, err := svc.TestAIProvider(r.Context(), &gateonv1.TestAIProviderRequest{})
		writeAIResponse(w, res, err)
	})
}

// writeAIResponse writes an advisory RPC's result. The RPCs fall back to the
// local analysis rather than fail, so an error here is unexpected.
func writeAIResponse(w http.ResponseWriter, msg proto.Message, err error) {
	if err != nil {
		WriteHTTPError(w, http.StatusInternalServerError, "the analysis could not be run")
		return
	}
	WriteProtoResponse(w, http.StatusOK, msg)
}
