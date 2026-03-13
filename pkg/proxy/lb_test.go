package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

func TestRoundRobinLB(t *testing.T) {
	targets := []string{"http://t1", "http://t2"}
	lb := NewRoundRobinLB(targets)

	// Test sequential selection
	t1 := lb.Next()
	if t1 != "http://t1" {
		t.Errorf("expected http://t1, got %s", t1)
	}

	t2 := lb.Next()
	if t2 != "http://t2" {
		t.Errorf("expected http://t2, got %s", t2)
	}

	t3 := lb.Next()
	if t3 != "http://t1" {
		t.Errorf("expected http://t1 (cycle), got %s", t3)
	}
}

func TestRoundRobinLB_SkipsDeadTargets(t *testing.T) {
	targets := []string{"http://t1", "http://t2", "http://t3"}
	lb := NewRoundRobinLB(targets)

	// Mark t1 and t3 as dead; only t2 is alive
	lb.SetAlive("http://t1", false)
	lb.SetAlive("http://t3", false)

	// All selections should return t2 (only alive target)
	for i := 0; i < 5; i++ {
		s := lb.NextState()
		if s == nil {
			t.Fatalf("iteration %d: expected target, got nil", i)
		}
		if s.url != "http://t2" {
			t.Errorf("iteration %d: expected http://t2 (only alive), got %s", i, s.url)
		}
	}
}

func TestRoundRobinLB_ReturnsNilWhenAllDead(t *testing.T) {
	targets := []string{"http://t1", "http://t2"}
	lb := NewRoundRobinLB(targets)
	lb.SetAlive("http://t1", false)
	lb.SetAlive("http://t2", false)

	s := lb.NextState()
	if s != nil {
		t.Errorf("expected nil when all targets dead, got %s", s.url)
	}
}

func TestLeastConnLB(t *testing.T) {
	targets := []string{"http://t1", "http://t2"}
	lb := NewLeastConnLB(targets)

	// Initial selection
	ts1 := lb.NextState()
	atomic.AddInt32(&ts1.activeConn, 1)

	// Second selection should pick t2 because t1 has 1 connection
	ts2 := lb.NextState()
	if ts2.url != "http://t2" {
		t.Errorf("expected http://t2 (least connections), got %s", ts2.url)
	}
	atomic.AddInt32(&ts2.activeConn, 1)

	// Both have 1 connection, should return a valid target
	ts3 := lb.NextState()
	if ts3 == nil || ts3.url == "" {
		t.Error("expected a target, got empty")
	}
}

func TestProxyHandler_SelectTarget(t *testing.T) {
	// Mock target servers
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s1.Close()

	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s2.Close()

	// Use LeastConnLB to test 'alive' logic as it implements skip-on-dead
	lb := NewLeastConnLB([]string{s1.URL, s2.URL})

	// Test picking a target
	ts := lb.NextState()
	if ts == nil || (ts.url != s1.URL && ts.url != s2.URL) {
		t.Errorf("picked unknown target: %v", ts)
	}

	// Test marking as dead via SetAlive (interface method)
	lb.SetAlive(ts.url, false)

	// Should pick the other one
	tsNext := lb.NextState()
	if tsNext == nil || tsNext.url == ts.url {
		t.Errorf("should not have picked dead target %v", tsNext)
	}
}

func TestGetStats_CircuitState(t *testing.T) {
	lb := NewRoundRobinLB([]string{"http://t1", "http://t2"})
	stats := lb.GetStats()
	if len(stats) != 2 {
		t.Fatalf("expected 2 stats, got %d", len(stats))
	}
	for i, s := range stats {
		if s.CircuitState != CircuitClosed {
			t.Errorf("stats[%d]: expected CircuitState CLOSED, got %s", i, s.CircuitState)
		}
	}
	lb.SetAlive("http://t1", false)
	stats = lb.GetStats()
	var openCount int
	for _, s := range stats {
		if s.CircuitState == CircuitOpen {
			openCount++
		}
	}
	if openCount != 1 {
		t.Errorf("expected 1 OPEN circuit after SetAlive, got %d", openCount)
	}
}

func TestLoadBalancerFactory(t *testing.T) {
	factory := NewDefaultLoadBalancerFactory()
	targets := []*gateonv1.Target{
		{Url: "http://a", Weight: 1},
		{Url: "http://b", Weight: 1},
	}
	lb := factory.Create("round_robin", targets)
	if lb == nil {
		t.Fatal("expected non-nil LoadBalancer")
	}
	stats := lb.GetStats()
	if len(stats) != 2 {
		t.Errorf("expected 2 targets, got %d", len(stats))
	}
	lb2 := factory.Create("least_conn", targets)
	if lb2 == nil {
		t.Fatal("expected non-nil LoadBalancer for least_conn")
	}
}
