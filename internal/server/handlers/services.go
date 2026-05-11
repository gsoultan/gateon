package handlers

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func registerServiceHandlers(mux *http.ServeMux, apiService *api.ApiService, d *Deps) {
	mux.HandleFunc("GET /v1/services", func(w http.ResponseWriter, r *http.Request) {
		page, pageSize, search := ParsePagination(r)
		svcs, total := d.ServiceService.ListPaginated(r.Context(), page, pageSize, search)
		WriteProtoResponse(w, http.StatusOK, &gateonv1.ListServicesResponse{
			Services: svcs, TotalCount: total, Page: page, PageSize: pageSize,
		})
	})
	mux.HandleFunc("PUT /v1/services", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceServices) {
			return
		}
		var svc gateonv1.Service
		if err := DecodeRequestBody(r, &svc); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := d.ServiceService.SaveService(r.Context(), &svc); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to save service")
			return
		}

		// Audit Log
		claims, _ := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
		userID := "system"
		if claims != nil {
			userID = claims.Username
		}
		audit.Log(r.Context(), userID, "save", "service", "Saved service: "+svc.Id, request.GetClientIP(r, true))

		WriteProtoResponse(w, http.StatusOK, &svc)
	})
	mux.HandleFunc("POST /v1/services/canary", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceServices) {
			return
		}
		var req gateonv1.StartCanaryRequest
		if err := DecodeRequestBody(r, &req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		taskID, err := d.CanaryService.StartCanary(r.Context(), &req)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to start canary deployment")
			return
		}
		WriteProtoResponse(w, http.StatusOK, &gateonv1.StartCanaryResponse{Success: true, TaskId: taskID})
	})
	mux.HandleFunc("DELETE /v1/services/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceServices) {
			return
		}
		id := r.PathValue("id")
		if id == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing service id")
			return
		}
		if err := d.ServiceService.DeleteService(r.Context(), id); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to delete service")
			return
		}

		// Audit Log
		claims, _ := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
		userID := "system"
		if claims != nil {
			userID = claims.Username
		}
		audit.Log(r.Context(), userID, "delete", "service", "Deleted service: "+id, request.GetClientIP(r, true))

		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("POST /v1/discover/grpc", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceServices) {
			return
		}
		var req gateonv1.DiscoverGrpcServicesRequest
		if err := DecodeRequestBody(r, &req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := apiService.DiscoverGrpcServices(r.Context(), &req)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteProtoResponse(w, http.StatusOK, resp)
	})
}
