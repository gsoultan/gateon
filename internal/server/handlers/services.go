package handlers

import (
	"net/http"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/google/uuid"
)

func registerServiceHandlers(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/services", func(w http.ResponseWriter, r *http.Request) {
		page, pageSize, search := ParsePagination(r)
		svcs, total := d.ServiceReg.ListPaginated(page, pageSize, search)
		WriteProtoResponse(w, http.StatusOK, &gateonv1.ListServicesResponse{
			Services: svcs, TotalCount: total, Page: page, PageSize: pageSize,
		})
	})
	mux.HandleFunc("PUT /v1/services", func(w http.ResponseWriter, r *http.Request) {
		var svc gateonv1.Service
		if err := DecodeRequestBody(r, &svc); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if svc.Id == "" {
			svc.Id = uuid.NewString()
		}
		if err := d.ServiceReg.Update(&svc); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to save service")
			return
		}
		d.InvalidateRouteProxies(func(rt *gateonv1.Route) bool { return rt.ServiceId == svc.Id })
		WriteProtoResponse(w, http.StatusOK, &svc)
	})
	mux.HandleFunc("DELETE /v1/services/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing service id")
			return
		}
		if err := d.ServiceReg.Delete(id); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to delete service")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
