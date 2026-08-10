// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gsoultan/gateon/internal/api"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func registerTracesHandlers(mux *http.ServeMux, apiService *api.ApiService) {
	mux.HandleFunc("GET /v1/traces", func(w http.ResponseWriter, r *http.Request) {
		limit := 100
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
				limit = l
			}
		}
		summary := r.URL.Query().Get("summary") == "true"

		resp, err := apiService.ListTraces(r.Context(), &gateonv1.ListTracesRequest{
			Limit:   int32(limit),
			Summary: summary,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		WriteProtoResponse(w, http.StatusOK, resp)
	})

	mux.HandleFunc("GET /v1/traces/detail", func(w http.ResponseWriter, r *http.Request) {
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
