package handlers

import (
	"net/http"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

func registerMiddlewareHandlers(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/middlewares", func(w http.ResponseWriter, r *http.Request) {
		page, pageSize, search := ParsePagination(r)
		mws, total := d.MwService.ListPaginated(page, pageSize, search)
		WriteProtoResponse(w, http.StatusOK, &gateonv1.ListMiddlewaresResponse{
			Middlewares: mws, TotalCount: total, Page: page, PageSize: pageSize,
		})
	})
	mux.HandleFunc("PUT /v1/middlewares", func(w http.ResponseWriter, r *http.Request) {
		var mw gateonv1.Middleware
		if err := DecodeRequestBody(r, &mw); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := d.MwService.SaveMiddleware(&mw); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to save middleware")
			return
		}
		WriteProtoResponse(w, http.StatusOK, &mw)
	})
	mux.HandleFunc("DELETE /v1/middlewares/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing middleware id")
			return
		}
		if err := d.MwService.DeleteMiddleware(id); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to delete middleware")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
