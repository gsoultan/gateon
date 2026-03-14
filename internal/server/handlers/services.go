package handlers

import (
	"net/http"

	"github.com/gateon/gateon/internal/auth"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

func registerServiceHandlers(mux *http.ServeMux, d *Deps) {
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
		WriteProtoResponse(w, http.StatusOK, &svc)
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
		w.WriteHeader(http.StatusNoContent)
	})
}
