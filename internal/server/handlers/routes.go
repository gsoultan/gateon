package handlers

import (
	"net/http"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/google/uuid"
)

func registerRouteHandlers(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/routes", func(w http.ResponseWriter, r *http.Request) {
		page, pageSize, search := ParsePagination(r)
		routes, total := d.RouteReg.ListPaginated(page, pageSize, search)
		WriteProtoResponse(w, http.StatusOK, &gateonv1.ListRoutesResponse{
			Routes: routes, TotalCount: total, Page: page, PageSize: pageSize,
		})
	})
	mux.HandleFunc("PUT /v1/routes", func(w http.ResponseWriter, r *http.Request) {
		var rt gateonv1.Route
		if err := DecodeRequestBody(r, &rt); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if rt.Rule == "" || rt.ServiceId == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing rule/service_id")
			return
		}
		if rt.Id == "" {
			rt.Id = uuid.NewString()
		}
		if err := d.RouteReg.Update(&rt); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to save route")
			return
		}
		d.InvalidateRouteProxy(rt.Id)
		WriteProtoResponse(w, http.StatusOK, &rt)
	})
	mux.HandleFunc("DELETE /v1/routes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing route id")
			return
		}
		if err := d.RouteReg.Delete(id); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to delete route")
			return
		}
		d.InvalidateRouteProxy(id)
		w.WriteHeader(http.StatusNoContent)
	})
}
