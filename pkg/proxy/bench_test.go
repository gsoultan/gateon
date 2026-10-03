// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/ai"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func BenchmarkServeHTTP(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	lb := NewRoundRobinLB([]string{backend.URL})
	h := &ProxyHandler{
		lb:               lb,
		routeType:        "http",
		stopDiscovery:    make(chan struct{}),
		stopHealthCheck:  make(chan struct{}),
		transport:        http.DefaultTransport,
		transportFactory: newBackendTransportFactory(nil, nil, nil),
	}
	defer h.Close()

	req := httptest.NewRequest("GET", "http://localhost/test", nil)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
	}
}

func BenchmarkServeHTTP_Parallel(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	lb := NewRoundRobinLB([]string{backend.URL})
	h := &ProxyHandler{
		lb:               lb,
		routeType:        "http",
		stopDiscovery:    make(chan struct{}),
		stopHealthCheck:  make(chan struct{}),
		transport:        http.DefaultTransport,
		transportFactory: newBackendTransportFactory(nil, nil, nil),
	}
	defer h.Close()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "http://localhost/test", nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
		}
	})
}

func BenchmarkRoundRobinLB_Next(b *testing.B) {
	lb := NewRoundRobinLB([]string{"http://localhost:8001", "http://localhost:8002", "http://localhost:8003"})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		lb.Next()
	}
}

// BenchmarkDefaultPolicyWeightedNext is the pick under the default policy, as
// the dashboard builds it: round robin, three targets weighted 1:2:6.
func BenchmarkDefaultPolicyWeightedNext(b *testing.B) {
	lb := NewDefaultLoadBalancerFactory().Create("round_robin", []*gateonv1.Target{
		{Url: "http://localhost:8001", Weight: 1},
		{Url: "http://localhost:8002", Weight: 2},
		{Url: "http://localhost:8003", Weight: 6},
	})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		lb.NextState()
	}
}

// BenchmarkDefaultPolicyNextOneDown is the same pick with one of three equal
// targets ejected by its health check, so a third of turns take the fallback.
func BenchmarkDefaultPolicyNextOneDown(b *testing.B) {
	lb := NewDefaultLoadBalancerFactory().Create("round_robin", []*gateonv1.Target{
		{Url: "http://localhost:8001", Weight: 1},
		{Url: "http://localhost:8002", Weight: 1},
		{Url: "http://localhost:8003", Weight: 1},
	})
	lb.SetAlive("http://localhost:8002", false)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		lb.NextState()
	}
}

// BenchmarkDefaultPolicyNext_Parallel is the equal-weight pick under
// contention, where every request shares the rotation counter.
func BenchmarkDefaultPolicyNext_Parallel(b *testing.B) {
	lb := NewDefaultLoadBalancerFactory().Create("round_robin", []*gateonv1.Target{
		{Url: "http://localhost:8001", Weight: 1},
		{Url: "http://localhost:8002", Weight: 1},
		{Url: "http://localhost:8003", Weight: 1},
	})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			lb.NextState()
		}
	})
}

func BenchmarkLeastConnLB_Next(b *testing.B) {
	lb := NewLeastConnLB([]string{"http://localhost:8001", "http://localhost:8002", "http://localhost:8003"})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		lb.Next()
	}
}

// BenchmarkAIPredictiveLB_NextAndRecord is one request's worth of balancer
// work under ai_predictive: the pick, and the latency report after the
// response. The predictor is installed, as it is in every running gateway.
func BenchmarkAIPredictiveLB_NextAndRecord(b *testing.B) {
	if err := ai.InitGlobalPredictor(context.Background(), ai.DefaultModelWasm); err != nil {
		b.Fatal(err)
	}
	lb := NewAIPredictiveLB([]*gateonv1.Target{
		{Url: "http://localhost:8001", Weight: 1},
		{Url: "http://localhost:8002", Weight: 1},
		{Url: "http://localhost:8003", Weight: 1},
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		lb.RecordLatency(lb.Next(), 0.01+float64(i%7)*0.001)
	}
}

func BenchmarkWeightedRoundRobinLB_Next(b *testing.B) {
	lb := NewWeightedRoundRobinLB([]*gateonv1.Target{
		{Url: "http://localhost:8001", Weight: 1},
		{Url: "http://localhost:8002", Weight: 2},
		{Url: "http://localhost:8003", Weight: 3},
	})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		lb.Next()
	}
}

func BenchmarkGetOrCreateProxy_CacheHit(b *testing.B) {
	lb := NewRoundRobinLB([]string{"http://localhost:8001"})
	h := &ProxyHandler{
		lb:               lb,
		routeType:        "http",
		stopDiscovery:    make(chan struct{}),
		stopHealthCheck:  make(chan struct{}),
		transport:        http.DefaultTransport,
		transportFactory: newBackendTransportFactory(nil, nil, nil),
	}
	defer h.Close()

	state := lb.set.Load().targets[0]
	// Prime the cache
	_ = h.getOrCreateProxy(state)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = h.getOrCreateProxy(state)
	}
}
