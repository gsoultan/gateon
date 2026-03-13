package handlers

import (
	"net/http"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

func registerTLSOptionHandlers(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/tls-options", func(w http.ResponseWriter, r *http.Request) {
		page, pageSize, search := ParsePagination(r)
		opts, total := d.TLSOptService.ListPaginated(r.Context(), page, pageSize, search)
		WriteProtoResponse(w, http.StatusOK, &gateonv1.ListTLSOptionsResponse{
			TlsOptions: opts, TotalCount: total, Page: page, PageSize: pageSize,
		})
	})
	mux.HandleFunc("PUT /v1/tls-options", func(w http.ResponseWriter, r *http.Request) {
		var opt gateonv1.TLSOption
		if err := DecodeRequestBody(r, &opt); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := d.TLSOptService.SaveTLSOption(r.Context(), &opt); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to save tls option")
			return
		}
		WriteProtoResponse(w, http.StatusOK, &opt)
	})
	mux.HandleFunc("DELETE /v1/tls-options/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing tls option id")
			return
		}
		if err := d.TLSOptService.DeleteTLSOption(r.Context(), id); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to delete tls option")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
