// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bufio"
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// CircuitBreakerConfig configures the circuit breaker middleware. A zero field
// takes the default named beside it.
type CircuitBreakerConfig struct {
	ErrorThreshold float64       // Error rate, 0 < rate <= 1, that opens the circuit (0.5)
	MinRequests    int64         // Requests a window must hold before its rate is judged (20)
	WindowSize     time.Duration // How long counts accumulate before starting over (10s)
	SleepWindow    time.Duration // How long the circuit stays open before one probe (30s)
	RouteID        string
	now            func() time.Time
}

const (
	defaultCBWindowSize  = 10 * time.Second
	defaultCBSleepWindow = 30 * time.Second
	defaultCBThreshold   = 0.5
	// defaultCBMinRequests is Hystrix's request-volume threshold. An unset
	// min_requests used to reach the breaker as zero, which judged a window on
	// its first request: one 5xx after a quiet spell was a 100% error rate.
	defaultCBMinRequests = 20
	// cbProbeRetryAfter is what a caller refused while the probe is out is told
	// to wait: the probe settles the circuit in about one backend round trip.
	cbProbeRetryAfter = time.Second
)

func (c CircuitBreakerConfig) withDefaults() CircuitBreakerConfig {
	if c.WindowSize <= 0 {
		c.WindowSize = defaultCBWindowSize
	}
	if c.SleepWindow <= 0 {
		c.SleepWindow = defaultCBSleepWindow
	}
	if c.ErrorThreshold <= 0 {
		c.ErrorThreshold = defaultCBThreshold
	}
	if c.MinRequests <= 0 {
		c.MinRequests = defaultCBMinRequests
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c
}

// circuitBreakerFromConfig builds the middleware from its stored settings. A
// value outside what the breaker can act on is refused rather than clamped: an
// error_threshold of 1.5 is never reached and one of -0.1 always is, so either
// would leave a route that reads as protected either unprotected or down.
func circuitBreakerFromConfig(cfg map[string]string, routeID string) (Middleware, error) {
	threshold, err := kind.ParseFloatStrict(cfg["error_threshold"], defaultCBThreshold)
	if err == nil && !(threshold > 0 && threshold <= 1) {
		err = errors.New("must be greater than 0 and at most 1")
	}
	if err != nil {
		return nil, kind.CfgError("error_threshold", cfg["error_threshold"], err)
	}
	minRequests, err := kind.ParseIntStrict(cfg["min_requests"], defaultCBMinRequests)
	if err == nil && minRequests < 1 {
		err = errors.New("must be at least 1")
	}
	if err != nil {
		return nil, kind.CfgError("min_requests", cfg["min_requests"], err)
	}
	windows := [2]time.Duration{}
	for i, key := range [2]string{"window_size", "sleep_window"} {
		d, err := kind.ParseDurationStrict(cfg[key], 0)
		if err == nil && cfg[key] != "" && d <= 0 {
			err = errors.New("must be a positive duration")
		}
		if err != nil {
			return nil, kind.CfgError(key, cfg[key], err)
		}
		windows[i] = d
	}
	return CircuitBreaker(CircuitBreakerConfig{
		ErrorThreshold: threshold,
		MinRequests:    int64(minRequests),
		WindowSize:     windows[0],
		SleepWindow:    windows[1],
		RouteID:        routeID,
	}), nil
}

// cbPhase packs what a breaker is doing with a generation that every
// transition bumps, so one atomic load says both. A request carries the phase
// it was admitted in and its outcome is dropped if the phase has moved on: a
// request admitted before the circuit opened says nothing about whether the
// backend has recovered since. Counting such failures is how a probe that
// proved the backend healthy used to re-open the circuit.
type cbPhase uint64

const (
	cbClosed cbPhase = iota
	cbOpen
	cbHalfOpen
	cbKindMask cbPhase = 3
)

func (p cbPhase) kind() cbPhase { return p & cbKindMask }

// next is the phase after a transition into kind k.
func (p cbPhase) next(k cbPhase) cbPhase { return (p&^cbKindMask + cbKindMask + 1) | k }

func (p cbPhase) circuitState() telemetry.CircuitState {
	switch p.kind() {
	case cbOpen:
		return telemetry.CircuitOpen
	case cbHalfOpen:
		return telemetry.CircuitHalfOpen
	default:
		return telemetry.CircuitClosed
	}
}

// circuitBreakerState is one route's breaker, shared by every chain built for
// the route so that a rebuild does not forget a failing backend. The request
// path touches only atomics; mu serialises transitions.
type circuitBreakerState struct {
	route    string
	mu       sync.Mutex
	phase    atomic.Uint64
	changed  atomic.Int64 // unix nanos of the last transition
	window   atomic.Int64 // unix nanos the current count window began
	requests atomic.Int64
	errors   atomic.Int64
	probing  atomic.Bool // the one request a half-open circuit admits is out
}

var (
	cbStates = make(map[string]*circuitBreakerState)
	cbMu     sync.Mutex
)

func getCBState(routeID string, now time.Time) *circuitBreakerState {
	cbMu.Lock()
	defer cbMu.Unlock()
	if s, ok := cbStates[routeID]; ok {
		return s
	}
	s := &circuitBreakerState{route: routeID}
	s.changed.Store(now.UnixNano())
	s.window.Store(now.UnixNano())
	publishCircuitState(routeID, cbClosed)
	cbStates[routeID] = s
	return s
}

// RetainCircuitBreakers forgets the breaker of every route label not in live,
// along with its state gauge. Without it a route deleted while its circuit
// was open would count as an open circuit on the dashboard until restart.
func RetainCircuitBreakers(live map[string]bool) {
	cbMu.Lock()
	defer cbMu.Unlock()
	for route := range cbStates {
		if !live[route] {
			delete(cbStates, route)
			telemetry.CircuitBreakerState.DeletePartialMatch(map[string]string{"route": route})
		}
	}
}

// publishCircuitState sets the route's state gauge: 1 for the state the
// breaker is in, 0 for the other two.
func publishCircuitState(route string, k cbPhase) {
	for _, s := range [3]cbPhase{cbClosed, cbOpen, cbHalfOpen} {
		v := 0.0
		if s == k {
			v = 1
		}
		telemetry.CircuitBreakerState.WithLabelValues(route, circuitStateLabel(s)).Set(v)
	}
}

func circuitStateLabel(k cbPhase) string {
	switch k {
	case cbOpen:
		return "open"
	case cbHalfOpen:
		return "half-open"
	default:
		return "closed"
	}
}

// CircuitBreaker returns a middleware that stops sending a route's traffic to a
// backend that is failing, and lets one request through after SleepWindow to
// find out whether it has recovered.
func CircuitBreaker(cfg CircuitBreakerConfig) Middleware {
	cfg = cfg.withDefaults()
	state := getCBState(cfg.RouteID, cfg.now())
	return func(next http.Handler) http.Handler {
		return &circuitBreaker{cfg: cfg, state: state, next: next}
	}
}

type circuitBreaker struct {
	cfg   CircuitBreakerConfig
	state *circuitBreakerState
	next  http.Handler
}

func (b *circuitBreaker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ticket, wait, ok := b.state.admit(&b.cfg)
	if !ok {
		w.Header().Set("Retry-After", retryAfterSeconds(wait))
		httputil.WriteJSONError(w, http.StatusServiceUnavailable, "service unavailable (circuit open)", "")
		return
	}
	if ticket.probe {
		b.serveProbe(w, r, ticket)
		return
	}
	// The writer passes through unchanged when it is already a
	// StatusResponseWriter: geoip tags it with the country and the recovery
	// middleware asks it whether headers went out, and both find it by type.
	sw, isStatusWriter := w.(*StatusResponseWriter)
	if !isStatusWriter {
		sw = GetStatusResponseWriter(w)
		defer PutStatusResponseWriter(sw)
	}
	b.next.ServeHTTP(sw, r)
	b.state.record(&b.cfg, ticket, sw.Status >= 500)
}

// serveProbe runs the half-open probe. It settles the circuit the moment its
// status is written (see probeWriter), and hands the probe slot back if the
// handler panics before writing one: kept, it would leave the circuit
// half-open and refusing everything for good.
func (b *circuitBreaker) serveProbe(w http.ResponseWriter, r *http.Request, t cbTicket) {
	pw := &probeWriter{ResponseWriter: w, breaker: b, ticket: t}
	returned := false
	defer func() {
		if !returned {
			b.state.abandon(t)
			return
		}
		pw.settle(false) // no status written: net/http sends 200
	}()
	b.next.ServeHTTP(pw, r)
	returned = true
}

// retryAfterSeconds rounds up and never says zero, which tells a client to
// retry at once.
func retryAfterSeconds(d time.Duration) string {
	return strconv.FormatInt(max(1, int64(math.Ceil(d.Seconds()))), 10)
}

// cbTicket is what an admitted request carries: the phase it was admitted in,
// and whether it is the half-open probe.
type cbTicket struct {
	phase cbPhase
	probe bool
}

// admit decides whether a request may reach the backend. A refused request is
// told how long to wait.
func (s *circuitBreakerState) admit(cfg *CircuitBreakerConfig) (cbTicket, time.Duration, bool) {
	p := cbPhase(s.phase.Load())
	switch p.kind() {
	case cbClosed:
		return cbTicket{phase: p}, 0, true
	case cbOpen:
		now := cfg.now()
		if wait := cfg.SleepWindow - now.Sub(time.Unix(0, s.changed.Load())); wait > 0 {
			return cbTicket{}, wait, false
		}
		s.transition(p, cbHalfOpen, now)
		p = cbPhase(s.phase.Load())
		if p.kind() != cbHalfOpen {
			return s.admit(cfg)
		}
	}
	if s.probing.CompareAndSwap(false, true) {
		return cbTicket{phase: p, probe: true}, 0, true
	}
	return cbTicket{}, cbProbeRetryAfter, false
}

// record settles an admitted request's outcome.
func (s *circuitBreakerState) record(cfg *CircuitBreakerConfig, t cbTicket, failed bool) {
	if t.probe {
		to := cbClosed
		if failed {
			to = cbOpen
		}
		s.transition(t.phase, to, cfg.now())
		return
	}
	if cbPhase(s.phase.Load()) != t.phase {
		return
	}
	now := cfg.now()
	if start := s.window.Load(); now.UnixNano()-start >= int64(cfg.WindowSize) &&
		s.window.CompareAndSwap(start, now.UnixNano()) {
		s.requests.Store(0)
		s.errors.Store(0)
	}
	requests := s.requests.Add(1)
	if !failed {
		return
	}
	errs := s.errors.Add(1)
	if requests >= cfg.MinRequests && float64(errs)/float64(requests) >= cfg.ErrorThreshold {
		s.transition(t.phase, cbOpen, now)
	}
}

// abandon hands back the probe slot of a probe that ended without a status.
// The circuit stays half-open and the next request probes instead.
func (s *circuitBreakerState) abandon(t cbTicket) {
	if !t.probe {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cbPhase(s.phase.Load()) == t.phase {
		s.probing.Store(false)
	}
}

// transition moves the breaker from phase from into kind to, unless another
// request has already moved it on.
func (s *circuitBreakerState) transition(from, to cbPhase, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cbPhase(s.phase.Load()) != from {
		return
	}
	s.requests.Store(0)
	s.errors.Store(0)
	s.window.Store(now.UnixNano())
	s.changed.Store(now.UnixNano())
	s.probing.Store(false)
	s.phase.Store(uint64(from.next(to)))

	publishCircuitState(s.route, to)
	telemetry.CircuitBreakerStateChangesTotal.WithLabelValues(s.route, "",
		circuitStateLabel(from.kind()), circuitStateLabel(to)).Inc()
	telemetry.RecordCircuitBreakerEvent(s.route, to.circuitState(), transitionReason(from.kind(), to))
}

func transitionReason(from, to cbPhase) string {
	switch {
	case to == cbHalfOpen:
		return "sleep window expired; probing"
	case from == cbHalfOpen && to == cbClosed:
		return "probe succeeded"
	case from == cbHalfOpen:
		return "probe failed"
	default:
		return "error rate exceeded threshold"
	}
}

// probeWriter settles the probe the moment its final status is known rather
// than when the handler returns. A probe that becomes a stream or a websocket
// has its answer long before it ends, and waiting for the end would hold the
// circuit half-open, refusing every other caller, for as long as that one
// connection stayed up.
type probeWriter struct {
	http.ResponseWriter
	breaker *circuitBreaker
	ticket  cbTicket
	settled bool
}

func (w *probeWriter) settle(failed bool) {
	if w.settled {
		return
	}
	w.settled = true
	w.breaker.state.record(&w.breaker.cfg, w.ticket, failed)
}

func (w *probeWriter) WriteHeader(code int) {
	// 1xx other than 101 is informational; the final status is still to come.
	if code >= 200 || code == http.StatusSwitchingProtocols {
		w.settle(code >= 500)
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *probeWriter) Write(b []byte) (int, error) {
	w.settle(false) // a body with no header is a 200
	return w.ResponseWriter.Write(b)
}

func (w *probeWriter) Flush() {
	w.settle(false)
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack settles on success: the proxy hijacks only once the backend has
// agreed to switch protocols.
func (w *probeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, rw, err := h.Hijack()
	if err == nil {
		w.settle(false)
	}
	return conn, rw, err
}

func (w *probeWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
