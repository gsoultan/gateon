// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/prometheus/client_golang/prometheus"
)

type transportContainer struct {
	p http.RoundTripper
}

type targetState struct {
	url                  string
	parsedURL            *url.URL // pre-parsed to avoid per-request url.Parse
	cacheKey             string   // pre-computed proxy cache key (scheme://host/path)
	transportScheme      string
	transportKey         string
	proxyProtocolEnabled bool
	proxyProtocolVersion gateonv1.ProxyProtocolVersion
	weight               int32
	// alive is read lock-free on the request hot path (e.g. RoundRobinLB.NextState
	// releases the LB lock before iterating) while the health checker writes it,
	// so it must be atomic to avoid a data race.
	alive           atomic.Bool
	requestCount    uint64
	errorCount      uint64
	latencySumUs    uint64
	activeConn      int32
	activeConnGuage prometheus.Gauge
	proxy           atomic.Pointer[httputil.ReverseProxy]
	transport       atomic.Value // stores *transportContainer
	// inflight holds a token for each request in flight to this target; nil
	// when the cap is off (BackendMaxInflight, review D3).
	inflight chan struct{}
}

// backendMaxInflight is how many requests may be in flight to one target:
// GATEON_BACKEND_MAX_INFLIGHT when it is an integer (0 or less is no cap),
// else the resource profile's (config.TierDefaults).
func backendMaxInflight() int {
	if v, ok := os.LookupEnv("GATEON_BACKEND_MAX_INFLIGHT"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return config.CurrentTierDefaults().BackendMaxInflight
}

// backendQueueTimeout is how long a request waits for a target at its cap:
// GATEON_BACKEND_QUEUE_TIMEOUT when it is a positive duration, else the
// resource profile's.
func backendQueueTimeout() time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("GATEON_BACKEND_QUEUE_TIMEOUT"))); err == nil && d > 0 {
		return d
	}
	return config.CurrentTierDefaults().BackendQueueTimeout
}

// acquire takes one of the target's in-flight slots, waiting up to
// backendQueueTimeout for one when all are taken. It is false when none
// freed in time or ctx ended first; the caller answers 503.
//
// Nothing capped this, so the connections to a backend were as many as an
// attacker could make the gateway hold requests for -- 18,822 descriptors in
// the 2026-11-13 rapid-reset experiment -- and the flood went on to the
// backend (review D3). The fast path is a non-blocking channel send and
// allocates nothing; only a request that has to wait pays for a timer.
func (s *targetState) acquire(ctx context.Context) bool {
	if s.inflight == nil {
		return true
	}
	select {
	case s.inflight <- struct{}{}:
		return true
	default:
	}
	t := time.NewTimer(backendQueueTimeout())
	defer t.Stop()
	select {
	case s.inflight <- struct{}{}:
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// release gives back a slot acquire took.
func (s *targetState) release() {
	if s.inflight != nil {
		<-s.inflight
	}
}

func newTargetState(rawURL string, weight int32) *targetState {
	return newTargetStateWithProxy(rawURL, weight, false, gateonv1.ProxyProtocolVersion_PROXY_PROTOCOL_VERSION_UNSPECIFIED)
}

func newTargetStateWithProxy(rawURL string, weight int32, proxyEnabled bool, proxyVersion gateonv1.ProxyProtocolVersion) *targetState {
	ts := &targetState{
		url:                  rawURL,
		weight:               weight,
		proxyProtocolEnabled: proxyEnabled,
		proxyProtocolVersion: proxyVersion,
		activeConnGuage:      telemetry.ActiveConnections.WithLabelValues(rawURL),
	}
	ts.alive.Store(true)
	if n := backendMaxInflight(); n > 0 {
		ts.inflight = make(chan struct{}, n)
	}
	if parsed, err := url.Parse(rawURL); err == nil {
		ts.transportScheme = parsed.Scheme
		// Normalize scheme for proxy cache key
		normalized := *parsed
		switch normalized.Scheme {
		case "h2c":
			normalized.Scheme = "http"
		case "h2", "h3":
			normalized.Scheme = "https"
		}
		ts.parsedURL = &normalized
		ts.cacheKey = normalized.Scheme + "://" + normalized.Host + normalized.Path
		ts.transportKey = normalized.Scheme + "|" + ts.transportScheme + "|" + rawURL
		if ts.proxyProtocolEnabled {
			ts.transportKey += "|pp:" + ts.proxyProtocolVersion.String()
		}
	}
	return ts
}

func newTargetStateFromTarget(target *gateonv1.Target) *targetState {
	if target == nil {
		return newTargetState("", 1)
	}
	return newTargetStateWithProxy(target.Url, target.Weight, target.ProxyProtocolEnabled, target.ProxyProtocolVersion)
}
