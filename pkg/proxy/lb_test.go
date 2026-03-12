package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
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

	// Test marking as dead
	ts.alive = false

	// Should pick the other one
	tsNext := lb.NextState()
	if tsNext == nil || tsNext.url == ts.url {
		t.Errorf("should not have picked dead target %v", tsNext)
	}
}
