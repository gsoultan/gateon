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

// BaseHandlerDeps holds narrow dependencies for CreateBaseHandler (Interface Segregation).
type BaseHandlerDeps struct {
	ProxyHandler http.Handler
	RouteStore   config.RouteStore
	GlobalReg    config.GlobalConfigStore
	ApiService   *api.ApiService
}

// CreateBaseHandler builds the main HTTP handler that routes to proxy or local API/UI.
func CreateBaseHandler(
	uiHandler http.Handler,
	deps BaseHandlerDeps,
	wrapped *grpcweb.WrappedGrpcServer,
	mux *http.ServeMux,
) http.Handler {
	handler := deps.ProxyHandler

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rt := router.SelectRoute(r, deps.RouteStore.List()); rt != nil {
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

		if gc := deps.GlobalReg.Get(); gc != nil && gc.Auth != nil && gc.Auth.Enabled && deps.ApiService.Auth != nil {
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
			middleware.PasetoAuth(deps.ApiService.Auth)(internal).ServeHTTP(w, r)
			return
		}

		internal.ServeHTTP(w, r)
	})
}
