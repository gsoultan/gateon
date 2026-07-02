package handlers

import (
	"net/http"
	"strconv"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func registerWafRuleHandlers(mux *http.ServeMux, apiService *api.ApiService) {
	mux.HandleFunc("GET /v1/waf/rules", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceWafRules) {
			return
		}

		query := r.URL.Query()
		limitStr := query.Get("limit")
		offsetStr := query.Get("offset")
		search := query.Get("search")

		var limit, offset int
		if limitStr != "" {
			var err error
			limit, err = strconv.Atoi(limitStr)
			if err != nil {
				WriteHTTPError(w, http.StatusBadRequest, "Invalid limit")
				return
			}
		}
		if offsetStr != "" {
			var err error
			offset, err = strconv.Atoi(offsetStr)
			if err != nil {
				WriteHTTPError(w, http.StatusBadRequest, "Invalid offset")
				return
			}
		}

		res, err := apiService.ListWafRules(r.Context(), &gateonv1.ListWafRulesRequest{
			Limit:  int32(limit),
			Offset: int32(offset),
			Search: search,
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
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
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
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteProtoResponse(w, http.StatusOK, res)
	})
}
