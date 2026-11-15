// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	wafmw "github.com/gsoultan/gateon/internal/middleware/security/waf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// effectiveWAFView is GET /v1/waf/effective: what the global WAF runs, and what
// each route WAF middleware runs once merged over it (ADR 0044). The dashboard
// reads switches and mode from here rather than from the stored booleans.
type effectiveWAFView struct {
	Global    wafmw.Effective     `json:"global"`
	RouteWAFs []effectiveRouteWAF `json:"routeWafs"`
}

type effectiveRouteWAF struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Effective wafmw.Effective `json:"effective"`
}

func buildEffectiveWAFView(ctx context.Context, apiService *api.ApiService) effectiveWAFView {
	store := apiService.GetGlobals()
	view := effectiveWAFView{Global: wafmw.EffectiveGlobal(ctx, store), RouteWAFs: []effectiveRouteWAF{}}
	if apiService.Middlewares == nil {
		return view
	}
	for _, mw := range apiService.Middlewares.List(ctx) {
		if !strings.EqualFold(mw.GetType(), "waf") {
			continue
		}
		view.RouteWAFs = append(view.RouteWAFs, effectiveRouteWAF{
			ID: mw.GetId(), Name: mw.GetName(), Effective: wafmw.EffectiveRoute(ctx, mw.GetConfig(), store),
		})
	}
	return view
}

func registerWafRuleHandlers(mux *http.ServeMux, apiService *api.ApiService) {
	mux.HandleFunc("GET /v1/waf/effective", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		WriteJSON(w, http.StatusOK, buildEffectiveWAFView(r.Context(), apiService))
	})

	mux.HandleFunc("GET /v1/waf/rules", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceWafRules) {
			return
		}

		page, pageSize, search := ParsePagination(r)
		category := r.URL.Query().Get("category")

		// Calculate offset from page
		offset := page * pageSize

		res, err := apiService.ListWafRules(r.Context(), &gateonv1.ListWafRulesRequest{
			Limit:    pageSize,
			Offset:   offset,
			Search:   search,
			Category: category,
		})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteProtoResponse(w, http.StatusOK, res)
	})

	// The rules compiled into the gateway, which the list above cannot show
	// because they are not rows. There is no write beside it.
	mux.HandleFunc("GET /v1/waf/rules/builtin", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceWafRules) {
			return
		}
		page, pageSize, search := ParsePagination(r)
		res, err := apiService.ListBuiltinWafRules(r.Context(), &gateonv1.ListBuiltinWafRulesRequest{
			Limit:    pageSize,
			Offset:   page * pageSize,
			Search:   search,
			Category: r.URL.Query().Get("category"),
		})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteProtoResponse(w, http.StatusOK, res)
	})

	mux.HandleFunc("POST /v1/waf/rules", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceWafRules) {
			return
		}
		var req gateonv1.CreateWafRuleRequest
		if err := DecodeRequestBody(r, &req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := apiService.CreateWafRule(r.Context(), &req)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteProtoResponse(w, http.StatusCreated, res)
	})

	mux.HandleFunc("PUT /v1/waf/rules", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceWafRules) {
			return
		}
		var req gateonv1.UpdateWafRuleRequest
		if err := DecodeRequestBody(r, &req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := apiService.UpdateWafRule(r.Context(), &req)
		if err != nil {
			writeRuleWriteError(w, err)
			return
		}
		WriteProtoResponse(w, http.StatusOK, res)
	})

	mux.HandleFunc("DELETE /v1/waf/rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceWafRules) {
			return
		}
		id := r.PathValue("id")
		res, err := apiService.DeleteWafRule(r.Context(), &gateonv1.DeleteWafRuleRequest{Id: id})
		if err != nil {
			writeRuleWriteError(w, err)
			return
		}
		WriteProtoResponse(w, http.StatusOK, res)
	})
}

// writeRuleWriteError answers a failed rule update or delete: a rule that is
// not there is 404, where it used to be a 200 that said the save had worked.
func writeRuleWriteError(w http.ResponseWriter, err error) {
	if status.Code(err) == codes.NotFound {
		WriteHTTPError(w, http.StatusNotFound, status.Convert(err).Message())
		return
	}
	WriteHTTPError(w, http.StatusInternalServerError, err.Error())
}
