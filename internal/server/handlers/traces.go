// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func registerTracesHandlers(mux *http.ServeMux, apiService *api.ApiService) {
	mux.HandleFunc("GET /v1/traces", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		// Bounded; see the diagnostics handlers for why the conversion, not the
		// input, is what produced a negative.
		limit := boundedInt32(r.URL.Query().Get("limit"), maxPageSize)
		if limit <= 0 {
			limit = 100
		}
		summary := r.URL.Query().Get("summary") == "true"

		resp, err := apiService.ListTraces(r.Context(), &gateonv1.ListTracesRequest{
			Limit:   limit,
			Summary: summary,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		WriteProtoResponse(w, http.StatusOK, resp)
	})

	mux.HandleFunc("GET /v1/traces/detail", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		id := r.URL.Query().Get("id")
		ts := r.URL.Query().Get("timestamp")

		if id == "" || ts == "" {
			http.Error(w, "missing id or timestamp", http.StatusBadRequest)
			return
		}

		resp, err := apiService.GetTrace(r.Context(), &gateonv1.GetTraceRequest{
			Id:        id,
			Timestamp: ts,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		WriteProtoResponse(w, http.StatusOK, resp)
	})
}
