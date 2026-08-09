// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func registerRouteHandlers(mux *http.ServeMux, d *Deps) {
	// Every route's target stats in one response.
	//
	// The dashboard draws a sparkline per route, and each one used to fetch its
	// own stats: one request per route, per refresh, forever. Seven routes cost
	// 21 requests every 30 seconds from a tab nobody was touching, and it grew
	// with the routing table rather than with what the operator was looking at.
	// On the 2-core host this is sized for, that is the gateway competing with
	// its own dashboard.
	//
	// Keyed by route ID so the client can fan it back out without another
	// lookup. A route with no stats is present with an empty list rather than
	// absent, so the caller can tell "no traffic" from "no such route".
	mux.HandleFunc("GET /v1/routes/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out := map[string][]proxy.TargetStats{}
		if d.RouteStatsProvider == nil || d.RouteService == nil {
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		// Page size 0 means "no limit" to ListPaginated; the dashboard needs
		// every route, not the first page of them.
		routes, _ := d.RouteService.ListPaginated(r.Context(), 0, 0, "", nil)
		for _, rt := range routes {
			stats := d.RouteStatsProvider(rt.GetId())
			if stats == nil {
				stats = []proxy.TargetStats{}
			}
			out[rt.GetId()] = stats
		}
		_ = json.NewEncoder(w).Encode(out)
	})
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

		// Audit Log
		claims, _ := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
		userID := "system"
		if claims != nil {
			userID = claims.Username
		}
		audit.Log(r.Context(), userID, "save", "route", "Saved route: "+rt.Id, request.GetClientIP(r, true))

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

		// Audit Log
		claims, _ := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
		userID := "system"
		if claims != nil {
			userID = claims.Username
		}
		audit.Log(r.Context(), userID, "delete", "route", "Deleted route: "+id, request.GetClientIP(r, true))

		w.WriteHeader(http.StatusNoContent)
	})
}
