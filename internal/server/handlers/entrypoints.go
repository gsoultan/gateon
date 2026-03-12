package handlers

import (
	"net/http"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

func registerEntryPointHandlers(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/entrypoints", func(w http.ResponseWriter, r *http.Request) {
		page, pageSize, search := ParsePagination(r)
		eps, total := d.EpService.ListPaginated(page, pageSize, search)
		WriteProtoResponse(w, http.StatusOK, &gateonv1.ListEntryPointsResponse{
			EntryPoints: eps, TotalCount: total, Page: page, PageSize: pageSize,
		})
	})
	mux.HandleFunc("PUT /v1/entrypoints", func(w http.ResponseWriter, r *http.Request) {
		var ep gateonv1.EntryPoint
		if err := DecodeRequestBody(r, &ep); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := d.EpService.SaveEntryPoint(&ep); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		WriteProtoResponse(w, http.StatusOK, &ep)
	})
	mux.HandleFunc("DELETE /v1/entrypoints/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing entrypoint id")
			return
		}
		if err := d.EpService.DeleteEntryPoint(id); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to delete entrypoint")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
