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

		resp, err := apiService.ListTraces(r.Context(), &gateonv1.ListTracesRequest{
			Limit: int32(limit),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		WriteProtoResponse(w, http.StatusOK, resp)
	})
}
