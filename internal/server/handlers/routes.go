package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func registerRouteHandlers(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/routes/{id}/stats", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing route id")
			return
		}
		if d.RouteStatsProvider == nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[]"))
			return
		}
		stats := d.RouteStatsProvider(id)
		if stats == nil {
			stats = []proxy.TargetStats{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stats)
	})
	mux.HandleFunc("GET /v1/routes", func(w http.ResponseWriter, r *http.Request) {
		page, pageSize, search := ParsePagination(r)
		filter := ParseRouteFilters(r)
		routes, total := d.RouteService.ListPaginated(r.Context(), page, pageSize, search, filter)
		WriteProtoResponse(w, http.StatusOK, &gateonv1.ListRoutesResponse{
			Routes: routes, TotalCount: total, Page: page, PageSize: pageSize,
		})
	})
	mux.HandleFunc("PUT /v1/routes", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceRoutes) {
			return
		}
		var rt gateonv1.Route
		if err := DecodeRequestBody(r, &rt); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := d.RouteService.SaveRoute(r.Context(), &rt); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		WriteProtoResponse(w, http.StatusOK, &rt)
	})
	mux.HandleFunc("DELETE /v1/routes/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceRoutes) {
			return
		}
		id := r.PathValue("id")
		if id == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing route id")
			return
		}
		if err := d.RouteService.DeleteRoute(r.Context(), id); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to delete route")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
