// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/middleware/traffic"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/internal/server/entrypoint"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// BenchmarkGatewayChain is what the gateway itself spends on one proxied
// request, with no network in the measurement: the entrypoint's chain as Run
// builds it, the base handler, route selection and the matched route's chain,
// down to where the proxy would take over. The proxy's own cost is
// pkg/proxy.BenchmarkServeHTTP.
//
// BenchmarkDataPlaneRequest measures the same path to a loopback backend, and
// on a shared host its loopback round trip is ~200µs with a spread wider than
// anything this chain costs, so a change to the chain cannot be told from
// noise there. Here the request, its URL and headers are rebuilt per iteration
// -- net/http gives every request fresh ones -- and nothing else is.
//
// The telemetry store is open and the tier is the default, so trace recording
// and per-request statistics run as they do in production. The access log is
// off because its line goes to stdout, where the benchmark's own output goes;
// BenchmarkAccessLogLine in internal/middleware prices that line on its own.
func BenchmarkGatewayChain(b *testing.B) {
	b.Setenv("GATEON_ACCESS_LOG_SAMPLE_RATE", "0")
	b.Setenv("GATEON_TRACE_DIR", filepath.Join(b.TempDir(), "traces"))
	_ = telemetry.ClosePathStatsStore(b.Context())
	if err := telemetry.InitPathStatsStore(filepath.Join(b.TempDir(), "telemetry.db"), 1); err != nil {
		b.Fatalf("init telemetry store: %v", err)
	}
	b.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	for _, bc := range []struct {
		name   string
		tracer func(b *testing.B)
	}{
		// What cmd/gateon runs with an OTLP endpoint configured: a span per
		// request, here recorded by a provider that exports nothing.
		{"tracing", func(b *testing.B) {
			prev := otel.GetTracerProvider()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
			otel.SetTracerProvider(tp)
			telemetry.SetTracingEnabled(true)
			b.Cleanup(func() {
				telemetry.SetTracingEnabled(false)
				otel.SetTracerProvider(prev)
				_ = tp.Shutdown(context.Background())
			})
		}},
		// The default: no endpoint, no span.
		{"no-tracing", func(*testing.B) {}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			bc.tracer(b)
			h := buildBenchGateway(b)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				req := benchGatewayRequest()
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, req)
				if rr.Code != http.StatusOK {
					b.Fatalf("status %d: %s", rr.Code, rr.Body.String())
				}
			}
		})
	}
}

var benchGatewayURL = &url.URL{Scheme: "http", Host: "gateway.test", Path: "/bench/items", RawQuery: "page=2"}

// benchGatewayRequest is one plaintext GET as the server would hand it over:
// its own Request, URL and Header, nothing shared between iterations.
func benchGatewayRequest() *http.Request {
	u := *benchGatewayURL
	return &http.Request{
		Method:     http.MethodGet,
		URL:        &u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"User-Agent": {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36"},
			"Accept":     {"application/json"},
			"Cookie":     {"theme=dark; _ga=GA1.2.3"},
		},
		Host:       "gateway.test",
		RemoteAddr: "192.0.2.10:40000",
		RequestURI: "/bench/items?page=2",
		Body:       http.NoBody,
	}
}

// buildBenchGateway is a plaintext data-plane entrypoint around the base
// handler, with one route whose chain ends in a handler answering 200 where
// the proxy would. The route's chain is built once and reused, as the proxy
// cache reuses a compiled route.
func buildBenchGateway(b *testing.B) http.Handler {
	b.Helper()
	tmp := b.TempDir()
	mgr, err := auth.NewManager(filepath.Join(tmp, "auth.db"), "0123456789abcdef0123456789abcdef", logger.Default())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = mgr.Close() })
	s, err := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(tmp, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(tmp, "services.json"))),
		WithEntryPointRegistry(config.NewEntryPointRegistry(filepath.Join(tmp, "entrypoints.json"))),
		WithMiddlewareRegistry(config.NewMiddlewareRegistry(filepath.Join(tmp, "middlewares.json"))),
		WithTLSOptionRegistry(config.NewTLSOptionRegistry(filepath.Join(tmp, "tls_options.json"))),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(tmp, "global.json"))),
		WithAuthManager(mgr),
	)
	if err != nil {
		b.Fatal(err)
	}
	if err := s.GlobalStore.Update(b.Context(), &gateonv1.GlobalConfig{
		Auth: &gateonv1.AuthConfig{Enabled: true, PasetoSecret: "0123456789abcdef0123456789abcdef"},
	}); err != nil {
		b.Fatal(err)
	}
	if err := s.ServiceStore.Update(b.Context(), &gateonv1.Service{
		Id: "bench", WeightedTargets: []*gateonv1.Target{{Url: "http://backend.bench.invalid", Weight: 1}},
	}); err != nil {
		b.Fatal(err)
	}
	if err := s.RouteStore.Update(b.Context(), &gateonv1.Route{
		Id: "bench", ServiceId: "bench", Type: "http", Rule: "Host(`gateway.test`) && PathPrefix(`/bench`)",
	}); err != nil {
		b.Fatal(err)
	}

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	// The route chain is built once, as the proxy cache would keep it, and
	// served to whatever request SelectRoute matched to the bench route.
	benchRoute := &gateonv1.Route{
		Id: "bench", ServiceId: "bench", Type: "http", Rule: "Host(`gateway.test`) && PathPrefix(`/bench`)",
	}
	routeChain := router.ApplyRouteMiddlewares(backend, benchRoute, nil, s.MwStore, s.GlobalStore, nil, nil)
	proxyDep := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs := middleware.GetRequestState(r)
		rt, _ := rs.MatchedRoute.(*gateonv1.Route)
		if rt == nil || rt.Id != benchRoute.Id {
			http.NotFound(w, r)
			return
		}
		routeChain.ServeHTTP(w, r)
	})
	mgmtOrigins := BuildManagementOrigins(&gateonv1.ManagementConfig{})
	base := CreateBaseHandler(http.NotFoundHandler(), BaseHandlerDeps{
		ProxyHandler: proxyDep,
		RouteStore:   s.RouteStore, GlobalReg: s.GlobalStore, Auth: s.AuthManager, MgmtOrigins: mgmtOrigins,
	}, nil, nil)

	ep := &gateonv1.EntryPoint{Id: "web", Name: "web", Address: ":8080", Type: gateonv1.EntryPoint_HTTP}
	deps := &entrypoint.Deps{
		Port:        "9090",
		EpStore:     s.EpStore,
		BaseHandler: base,
		Limiter:     traffic.NoopRateLimiter{},
		GlobalStore: s.GlobalStore,
	}
	return middleware.Chain(entrypoint.Chain(b.Context(), ep, deps)...)(deps.Limiter.Handler(traffic.PerIP)(base))
}
