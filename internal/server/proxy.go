package server

import (
	"net/http"
	"strings"

	"github.com/gateon/gateon/internal/middleware"
	"github.com/gateon/gateon/internal/router"
	"github.com/gateon/gateon/pkg/proxy"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// GetOrCreateProxy returns a cached proxy handler for the route or creates one.
func (s *Server) GetOrCreateProxy(rt *gateonv1.Route) http.Handler {
	s.ProxiesMu.RLock()
	h, ok := s.Proxies[rt.Id]
	s.ProxiesMu.RUnlock()
	if ok {
		return h
	}
	s.ProxiesMu.Lock()
	defer s.ProxiesMu.Unlock()
	if h, ok = s.Proxies[rt.Id]; ok {
		return h
	}
	pHandler := proxy.NewProxyHandler(rt, s.ServiceReg)
	h = router.ApplyRouteMiddlewares(pHandler, rt, s.RedisClient, s.MwReg)
	s.Proxies[rt.Id] = h
	return h
}

// HandleProxyOrLocal routes the request to a proxied backend or to the local mux/gRPC.
func (s *Server) HandleProxyOrLocal(w http.ResponseWriter, r *http.Request, wrapped *grpcweb.WrappedGrpcServer, mux *http.ServeMux) {
	isGRPC := (r.ProtoMajor == 2 || r.ProtoMajor == 3) && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
	isGRPCWeb := wrapped.IsGrpcWebRequest(r) || wrapped.IsAcceptableGrpcCorsRequest(r) || wrapped.IsGrpcWebSocketRequest(r)

	if rt := router.SelectRoute(r, s.RouteReg.List()); rt != nil {
		if rt.Tls != nil && r.TLS == nil {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("HTTPS required"))
			return
		}
		if ((isGRPC || isGRPCWeb) && strings.EqualFold(rt.Type, "grpc")) || (!isGRPC && !isGRPCWeb) {
			h := s.GetOrCreateProxy(rt)
			if h == nil {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if isGRPCWeb && strings.EqualFold(rt.Type, "grpc") {
				middleware.GRPCWeb()(h).ServeHTTP(w, r)
				return
			}
			h.ServeHTTP(w, r)
			return
		}
	}
	if isGRPC || isGRPCWeb {
		wrapped.ServeHTTP(w, r)
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
	if routeID == "" {
		return
	}
	s.ProxiesMu.Lock()
	defer s.ProxiesMu.Unlock()
	s.invalidateProxy(routeID)
}

// InvalidateRouteProxies removes cached proxies for routes matching the strategy.
func (s *Server) InvalidateRouteProxies(strategy func(*gateonv1.Route) bool) {
	if strategy == nil {
		return
	}
	s.ProxiesMu.Lock()
	defer s.ProxiesMu.Unlock()
	for _, rt := range s.RouteReg.List() {
		if strategy(rt) {
			s.invalidateProxy(rt.Id)
		}
	}
}

func (s *Server) invalidateProxy(id string) {
	if old, ok := s.Proxies[id]; ok {
		type closer interface{ Close() }
		if c, ok := old.(closer); ok {
			c.Close()
		} else if ph, ok := old.(*proxy.ProxyHandler); ok {
			ph.Close()
		} else if wh, ok := old.(interface{ Unwrap() http.Handler }); ok {
			if c, ok := wh.Unwrap().(closer); ok {
				c.Close()
			}
		}
	}
	delete(s.Proxies, id)
}

// SyncProxies runs periodic proxy cache maintenance (e.g. logging).
func (s *Server) SyncProxies() {
	s.ProxiesMu.Lock()
	defer s.ProxiesMu.Unlock()
	// Optional: cleanup or metrics
	_ = len(s.Proxies)
}
