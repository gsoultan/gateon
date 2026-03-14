package server

import (
	"net/http"
	"strings"

	"github.com/gateon/gateon/internal/router"
	"github.com/gateon/gateon/internal/server/entrypoint"
	"github.com/gateon/gateon/pkg/proxy"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
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
	isGRPC := (r.ProtoMajor == 2 || r.ProtoMajor == 3) && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
	isGRPCWeb := internalAPI != nil && (internalAPI.IsGrpcWebRequest(r) || internalAPI.IsAcceptableGrpcCorsRequest(r) || internalAPI.IsGrpcWebSocketRequest(r))

	if rt := router.SelectRoute(r, s.RouteStore.List(r.Context())); rt != nil {
		if rt.Tls != nil && r.TLS == nil {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("HTTPS required"))
			return
		}
		if ((isGRPC || isGRPCWeb) && strings.EqualFold(rt.Type, "grpc")) || (!isGRPC && !isGRPCWeb) {
			if isGRPCWeb && strings.EqualFold(rt.Type, "grpc") && !router.RouteHasMiddlewareType(r.Context(), rt, s.MwStore, "grpcweb") {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				_, _ = w.Write([]byte("gRPC-Web requires the grpcweb middleware on this route"))
				return
			}
			h := s.GetOrCreateProxy(rt)
			if h == nil {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			h.ServeHTTP(w, r)
			return
		}
	}
	if isGRPC || isGRPCWeb {
		if internalAPI != nil {
			// Internal API: dashboard gRPC-Web (no matching user route)
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
