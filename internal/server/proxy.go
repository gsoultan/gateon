package server

import (
	"cmp"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/internal/server/entrypoint"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// GetOrCreateProxy returns a cached proxy handler for the route or creates one.
func (s *Server) GetOrCreateProxy(rt *gateonv1.Route) http.Handler {
	return s.proxyCache().GetOrCreate(rt)
}

// HandleProxyOrLocal routes the request to a proxied backend or to the local mux/gRPC.
// gRPC-Web: conversion happens only when the route has the grpcweb middleware.
// Internal API: no matching route -> internalAPI (dashboard); origin allow-all.
func (s *Server) HandleProxyOrLocal(w http.ResponseWriter, r *http.Request, internalAPI entrypoint.GRPCWebHandler, mux *http.ServeMux) {
	isMgmt := false
	if rs := middleware.GetRequestState(r); rs != nil {
		isMgmt = rs.IsManagement
	} else if m, ok := r.Context().Value(middleware.IsManagementContextKey).(bool); ok {
		isMgmt = m
	}

	// 1. Try to find and handle a user-defined route first (priority)
	if !isMgmt {
		var rt *gateonv1.Route
		if rs := middleware.GetRequestState(r); rs != nil {
			if matched, ok := rs.MatchedRoute.(*gateonv1.Route); ok {
				rt = matched
			}
		}
		if rt == nil {
			rt, _ = r.Context().Value(middleware.MatchedRouteContextKey).(*gateonv1.Route)
		}
		if rt == nil {
			rt = router.SelectRoute(r, s.RouteStore)
		}

		if rt != nil {
			if logger.L.IsEnabled(slog.LevelDebug) {
				logger.L.LogDebug("Route matched",
					"flow_step", "route_match",
					"request_id", middleware.GetRequestID(r),
					"route", cmp.Or(rt.Name, rt.Id),
					"rule", rt.Rule)
			}

			// Security: Enforce HTTPS if configured for the route
			if rt.Tls != nil && r.TLS == nil {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("HTTPS required"))
				return
			}

			// Protocol Check: Only for gRPC routes, verify gRPC-Web requirements
			if (strings.EqualFold(rt.Type, "grpc") || strings.EqualFold(rt.Type, "grpc-web")) && internalAPI != nil {
				// We use a stricter check here for actual gRPC-Web payloads
				if internalAPI.IsGrpcWebRequest(r) || internalAPI.IsGrpcWebSocketRequest(r) {
					if !router.RouteHasMiddlewareType(r.Context(), rt, s.MwStore, "grpcweb") {
						w.WriteHeader(http.StatusUnsupportedMediaType)
						_, _ = w.Write([]byte("gRPC-Web requires the grpcweb middleware on this route"))
						return
					}
				}
			}

			// Execute proxy
			h := s.GetOrCreateProxy(rt)
			if h != nil {
				h.ServeHTTP(w, r)
				return
			}
			w.WriteHeader(http.StatusBadGateway)
			return
		}
	}

	// 2. Fallback to Internal API (Dashboard), Metrics, or Mux
	// We only use the dashboard gRPC-Web handler if no user route matched.
	isGRPC := (r.ProtoMajor >= 2) && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
	isGRPCWeb := internalAPI != nil && (internalAPI.IsGrpcWebRequest(r) || internalAPI.IsAcceptableGrpcCorsRequest(r) || internalAPI.IsGrpcWebSocketRequest(r))

	// Broaden OPTIONS detection for dashboard preflights if not already caught
	if !isGRPCWeb && r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") == "POST" {
		isGRPCWeb = true
	}

	if isGRPC || isGRPCWeb {
		if internalAPI != nil {
			internalAPI.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusNotImplemented)
		}
		return
	}

	if r.URL.Path == "/metrics" {
		promhttp.Handler().ServeHTTP(w, r)
		return
	}

	mux.ServeHTTP(w, r)
}

// InvalidateRouteProxy removes the cached proxy for the given route ID.
func (s *Server) InvalidateRouteProxy(routeID string) {
	s.proxyCache().InvalidateRoute(routeID)
}

// InvalidateRouteProxies removes cached proxies for routes matching the strategy.
func (s *Server) InvalidateRouteProxies(strategy func(*gateonv1.Route) bool) {
	s.proxyCache().InvalidateRoutes(strategy)
}

// GetRouteStats returns target stats for a route, or nil if not found.
func (s *Server) GetRouteStats(routeID string) []proxy.TargetStats {
	return s.proxyCache().GetRouteStats(routeID)
}

// SyncProxies runs periodic proxy cache maintenance (e.g. metrics).
func (s *Server) SyncProxies() {
	s.proxyCache().Sync()
}
