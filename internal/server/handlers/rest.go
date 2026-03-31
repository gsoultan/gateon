package handlers

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/api"
)

// RegisterRESTHandlers registers all REST handlers on mux (routes, services, entrypoints, etc.).
func RegisterRESTHandlers(mux *http.ServeMux, apiService *api.ApiService, d *Deps) {
	registerOpenAPI(mux)
	registerRouteHandlers(mux, d)
	registerConfigImportExport(mux, d)
	registerEntryPointHandlers(mux, d)
	registerMiddlewareHandlers(mux, d)
	registerServiceHandlers(mux, d)
	registerTLSOptionHandlers(mux, d)
	registerGlobalHandlers(mux, apiService, d)
	registerCertHandlers(mux, apiService)
	registerDiagnosticHandlers(mux, d)
	registerAIHandlers(mux, d)
	registerTracesHandlers(mux, apiService)
}
