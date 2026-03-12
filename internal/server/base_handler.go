package server

import (
	"net/http"
	"strings"

	"github.com/gateon/gateon/internal/api"
	"github.com/gateon/gateon/internal/config"
	"github.com/gateon/gateon/internal/middleware"
	"github.com/gateon/gateon/internal/router"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
)

// CreateBaseHandler builds the main HTTP handler that routes to proxy or local API/UI.
func CreateBaseHandler(
	uiHandler http.Handler,
	s *Server,
	globalReg *config.GlobalRegistry,
	apiService *api.ApiService,
	wrapped *grpcweb.WrappedGrpcServer,
	mux *http.ServeMux,
) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, wrapped, mux)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rt := router.SelectRoute(r, s.RouteReg.List()); rt != nil {
			handler.ServeHTTP(w, r)
			return
		}

		internal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/metrics" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				handler.ServeHTTP(w, r)
				return
			}
			uiHandler.ServeHTTP(w, r)
		})

		if gc := globalReg.Get(); gc != nil && gc.Auth != nil && gc.Auth.Enabled && apiService.Auth != nil {
			isAPI := strings.HasPrefix(r.URL.Path, "/v1/")
			isMetrics := r.URL.Path == "/metrics"
			isLogin := r.URL.Path == "/v1/login"
			isSetup := r.URL.Path == "/v1/setup" || r.URL.Path == "/v1/setup/required"
			isHealth := r.URL.Path == "/healthz" || r.URL.Path == "/readyz"
			isStatus := r.URL.Path == "/v1/status"

			if !isAPI && !isMetrics {
				internal.ServeHTTP(w, r)
				return
			}
			if isLogin || isSetup || isHealth || isStatus {
				internal.ServeHTTP(w, r)
				return
			}
			if r.URL.Path == "/v1/logs" && r.Header.Get("Authorization") == "" {
				if auth := r.URL.Query().Get("auth"); auth != "" {
					r.Header.Set("Authorization", "Bearer "+auth)
				}
			}
			middleware.PasetoAuth(apiService.Auth)(internal).ServeHTTP(w, r)
			return
		}

		internal.ServeHTTP(w, r)
	})
}
