package handlers

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.json
var openAPISpec []byte

// registerOpenAPI serves the OpenAPI spec at GET /v1/openapi.json.
func registerOpenAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(openAPISpec)
	})
}
