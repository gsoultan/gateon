// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/security/reputation"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestThreatDetectionBoundsConcurrentProviderLookups: a pass over many
// addresses must not ask the threat-intelligence provider about all of them at
// once. Root cause: Detect started one goroutine per address, each of which
// could call the provider, so the number of outbound lookups in flight was the
// number of addresses the attacker chose to use.
func TestThreatDetectionBoundsConcurrentProviderLookups(t *testing.T) {
	const addresses = 64
	feed := &blockingFeed{release: make(chan struct{}), reached: make(chan struct{})}
	prev := http.DefaultTransport
	http.DefaultTransport = feed
	t.Cleanup(func() { http.DefaultTransport = prev })
	store := reputation.NewIPReputationStore(&gateonv1.IPReputationConfig{
		Enabled: true,
		Integrations: []*gateonv1.IPReputationIntegration{{
			Id: "a", Name: "AbuseIPDB", Type: "abuseipdb", ApiKey: "k", Enabled: true,
		}},
	})
	d := &SecurityThreatDetector{Threshold: 5, Reputation: store}
	data := &DiagnosticData{IPStats: map[string]*IPStats{}}
	for i := range addresses {
		data.IPStats["198.51.100."+strconv.Itoa(i)] = &IPStats{TotalRequests: 11, LastSeen: time.Now()}
	}

	done := make(chan struct{})
	go func() { defer close(done); d.Detect(t.Context(), data) }()
	select {
	case <-feed.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the pass never filled its lookup slots")
	}
	// Give any lookups past the bound the chance to start before letting
	// the held ones finish.
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
	}
	close(feed.release)
	<-done

	if got := feed.peak(); got > threatAnalysisWorkers {
		t.Fatalf("%d provider lookups were in flight at once, want at most %d", got, threatAnalysisWorkers)
	}
}

// blockingFeed answers AbuseIPDB's check endpoint, holding every request until
// release is closed, and records how many were held at once.
type blockingFeed struct {
	mu       sync.Mutex
	inFlight int
	max      int
	once     sync.Once
	reached  chan struct{}
	release  chan struct{}
}

func (f *blockingFeed) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.inFlight++
	f.max = max(f.max, f.inFlight)
	if f.inFlight >= threatAnalysisWorkers {
		f.once.Do(func() { close(f.reached) })
	}
	f.mu.Unlock()
	<-f.release
	f.mu.Lock()
	f.inFlight--
	f.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"data":{"abuseConfidenceScore":0}}`)),
		Request:    r,
	}, nil
}

func (f *blockingFeed) peak() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.max
}
