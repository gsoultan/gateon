package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkServeHTTP(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	lb := NewRoundRobinLB([]string{backend.URL})
	h := &ProxyHandler{
		lb:              lb,
		routeType:       "http",
		stopDiscovery:   make(chan struct{}),
		stopHealthCheck: make(chan struct{}),
		transport:       http.DefaultTransport,
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
		lb:              lb,
		routeType:       "http",
		stopDiscovery:   make(chan struct{}),
		stopHealthCheck: make(chan struct{}),
		transport:       http.DefaultTransport,
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

func BenchmarkLeastConnLB_Next(b *testing.B) {
	lb := NewLeastConnLB([]string{"http://localhost:8001", "http://localhost:8002", "http://localhost:8003"})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		lb.Next()
	}
}

func BenchmarkGetOrCreateProxy_CacheHit(b *testing.B) {
	lb := NewRoundRobinLB([]string{"http://localhost:8001"})
	h := &ProxyHandler{
		lb:              lb,
		routeType:       "http",
		stopDiscovery:   make(chan struct{}),
		stopHealthCheck: make(chan struct{}),
		transport:       http.DefaultTransport,
	}
	defer h.Close()

	state := lb.targets[0]
	// Prime the cache
	_ = h.getOrCreateProxy(state.cacheKey, state.parsedURL)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = h.getOrCreateProxy(state.cacheKey, state.parsedURL)
	}
}
