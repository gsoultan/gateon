// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bufio"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// breakerClock is a clock the test moves by hand, so a sleep window can pass
// without the test sleeping through it.
type breakerClock struct{ ns atomic.Int64 }

func newBreakerClock() *breakerClock {
	c := &breakerClock{}
	c.ns.Store(time.Now().UnixNano())
	return c
}

func (c *breakerClock) Now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *breakerClock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

// breakerBackend answers each request with the status in its X-Status header.
// X-Hold parks the request in the backend until the test releases it -- a
// request in flight while the circuit changes state. X-Stream does the same
// after the status has been written, the shape of an SSE or gRPC stream.
type breakerBackend struct {
	arrived chan struct{}
	release chan struct{}
}

func (b *breakerBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Panic") != "" {
		panic(http.ErrAbortHandler)
	}
	code, _ := strconv.Atoi(r.Header.Get("X-Status"))
	if r.Header.Get("X-Stream") != "" {
		w.WriteHeader(code)
		b.arrived <- struct{}{}
		<-b.release
		return
	}
	if r.Header.Get("X-Hold") != "" {
		b.arrived <- struct{}{}
		<-b.release
	}
	w.WriteHeader(code)
}

type breakerRig struct {
	t       *testing.T
	clock   *breakerClock
	backend *breakerBackend
	h       http.Handler
}

func newBreakerRig(t *testing.T, cfg CircuitBreakerConfig) *breakerRig {
	t.Helper()
	clock := newBreakerClock()
	cfg.RouteID = t.Name()
	cfg.now = clock.Now
	b := &breakerBackend{arrived: make(chan struct{}), release: make(chan struct{})}
	return &breakerRig{t: t, clock: clock, backend: b, h: CircuitBreaker(cfg)(b)}
}

func (r *breakerRig) request(status int, header string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Status", strconv.Itoa(status))
	if header != "" {
		req.Header.Set(header, "1")
	}
	return req
}

// do sends one request the backend answers with status.
func (r *breakerRig) do(status int) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, r.request(status, ""))
	return rec
}

// park starts a request that waits in the backend (header is X-Hold or
// X-Stream) and returns once the backend has it. A request the breaker refuses
// never gets there, which fails the test rather than hanging it.
func (r *breakerRig) park(status int, header string) <-chan *httptest.ResponseRecorder {
	r.t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		r.h.ServeHTTP(rec, r.request(status, header))
		done <- rec
	}()
	select {
	case <-r.backend.arrived:
	case rec := <-done:
		r.t.Fatalf("parked request answered %d without reaching the backend", rec.Code)
	case <-time.After(10 * time.Second):
		r.t.Fatal("parked request never reached the backend")
	}
	return done
}

// finish releases the parked request and returns what its client got.
func (r *breakerRig) finish(done <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	r.t.Helper()
	r.backend.release <- struct{}{}
	select {
	case rec := <-done:
		return rec
	case <-time.After(10 * time.Second):
		r.t.Fatal("released request never completed")
		return nil
	}
}

// open trips a breaker configured with MinRequests 1: one failure once the
// window has run.
func (r *breakerRig) open() {
	r.t.Helper()
	r.clock.Advance(11 * time.Second)
	if code := r.do(http.StatusInternalServerError).Code; code != http.StatusInternalServerError {
		r.t.Fatalf("failing request answered %d, want the backend's 500", code)
	}
	if code := r.do(http.StatusOK).Code; code != http.StatusServiceUnavailable {
		r.t.Fatalf("after a failure over MinRequests 1, a request answered %d, want 503 from an open circuit", code)
	}
}

func quickBreaker() CircuitBreakerConfig {
	return CircuitBreakerConfig{MinRequests: 1, WindowSize: 10 * time.Second, SleepWindow: 30 * time.Second}
}

// TestHalfOpenCircuitAdmitsOneProbe: a half-open circuit is a question -- has
// the backend recovered? -- and one request answers it. The breaker used to let
// every request through while half-open, so the traffic that had been held off
// for the whole sleep window arrived at the struggling backend at once.
func TestHalfOpenCircuitAdmitsOneProbe(t *testing.T) {
	rig := newBreakerRig(t, quickBreaker())
	rig.open()

	rig.clock.Advance(31 * time.Second)
	probe := rig.park(http.StatusOK, "X-Hold")
	for i := range 5 {
		rec := rig.do(http.StatusOK)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("request %d while the probe was out answered %d, want 503: "+
				"a half-open circuit admits one probe, not everyone", i, rec.Code)
		}
		if got := rec.Header().Get("Retry-After"); got != "1" {
			t.Errorf("Retry-After while the probe is out = %q, want \"1\": the probe "+
				"settles the circuit in about one round trip", got)
		}
	}
	if rec := rig.finish(probe); rec.Code != http.StatusOK {
		t.Fatalf("probe answered %d, want the backend's 200", rec.Code)
	}
	if code := rig.do(http.StatusOK).Code; code != http.StatusOK {
		t.Fatalf("after a successful probe a request answered %d, want 200 from a closed circuit", code)
	}
}

// TestSuccessfulProbeIsNotUndoneByFailuresFromBeforeTheTrip: a request in
// flight when the circuit opens fails a moment later, and that failure belongs
// to the outage the breaker already acted on. The breaker counted it against
// the half-open window anyway, so the probe that proved the backend healthy
// re-opened the circuit for another sleep window.
func TestSuccessfulProbeIsNotUndoneByFailuresFromBeforeTheTrip(t *testing.T) {
	rig := newBreakerRig(t, quickBreaker())
	stale := rig.park(http.StatusInternalServerError, "X-Hold")
	rig.open()
	if rec := rig.finish(stale); rec.Code != http.StatusInternalServerError {
		t.Fatalf("stale request answered %d, want the backend's 500", rec.Code)
	}

	rig.clock.Advance(31 * time.Second)
	if code := rig.do(http.StatusOK).Code; code != http.StatusOK {
		t.Fatalf("probe answered %d, want 200", code)
	}
	if code := rig.do(http.StatusOK).Code; code != http.StatusOK {
		t.Fatalf("after a successful probe a request answered %d, want 200: a failure "+
			"from before the circuit opened re-opened it", code)
	}
}

// TestFailedProbeReopensForAFullSleepWindow is the other half of recovery.
func TestFailedProbeReopensForAFullSleepWindow(t *testing.T) {
	rig := newBreakerRig(t, quickBreaker())
	rig.open()

	rig.clock.Advance(31 * time.Second)
	if code := rig.do(http.StatusBadGateway).Code; code != http.StatusBadGateway {
		t.Fatalf("probe answered %d, want the backend's 502", code)
	}
	rec := rig.do(http.StatusOK)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("after a failed probe a request answered %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Errorf("Retry-After after a failed probe = %q, want the whole sleep window, \"30\"", got)
	}
}

// TestAnUnsetMinimumDoesNotOpenOnOneFailure: min_requests left out of the
// config reached the breaker as zero, so a window was judged on however many
// requests it held -- one 5xx after a quiet spell was a 100% error rate and
// took the route down for thirty seconds.
func TestAnUnsetMinimumDoesNotOpenOnOneFailure(t *testing.T) {
	rig := newBreakerRig(t, CircuitBreakerConfig{WindowSize: 10 * time.Second})
	rig.clock.Advance(11 * time.Second)
	rig.do(http.StatusInternalServerError)
	if code := rig.do(http.StatusOK).Code; code != http.StatusOK {
		t.Fatalf("after one failure with min_requests unset a request answered %d, "+
			"want 200: one request is not a sample", code)
	}
	// Twenty requests, nineteen of them failures: a sample, and a bad one.
	for range 18 {
		rig.do(http.StatusInternalServerError)
	}
	if code := rig.do(http.StatusOK).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("after 19 failures in 20 requests a request answered %d, want 503", code)
	}
}

// TestBreakerJudgesAWindowOnlyOnceItHoldsMinRequests pins the guard that keeps
// a breaker from tripping on a tiny sample.
func TestBreakerJudgesAWindowOnlyOnceItHoldsMinRequests(t *testing.T) {
	rig := newBreakerRig(t, CircuitBreakerConfig{MinRequests: 10, WindowSize: time.Minute})
	rig.do(http.StatusInternalServerError)
	rig.do(http.StatusInternalServerError)
	if code := rig.do(http.StatusOK).Code; code != http.StatusOK {
		t.Fatalf("after 2 failures in 3 requests against MinRequests 10 a request "+
			"answered %d, want 200", code)
	}
	for range 7 {
		rig.do(http.StatusInternalServerError)
	}
	if code := rig.do(http.StatusOK).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("after 9 failures in 10 requests a request answered %d, want 503", code)
	}
}

// TestRetryAfterIsTheTimeLeftInTheSleepWindow: Retry-After was a constant
// thirty seconds whatever sleep_window said, so a client honouring it came
// back before a two-minute circuit could admit it, or waited half a minute
// for a five-second one.
func TestRetryAfterIsTheTimeLeftInTheSleepWindow(t *testing.T) {
	cfg := quickBreaker()
	cfg.SleepWindow = 2 * time.Minute
	rig := newBreakerRig(t, cfg)
	rig.open()

	rig.clock.Advance(30 * time.Second)
	if got := rig.do(http.StatusOK).Header().Get("Retry-After"); got != "90" {
		t.Errorf("Retry-After 30s into a 2m sleep window = %q, want \"90\"", got)
	}
	rig.clock.Advance(59*time.Second + 500*time.Millisecond)
	if got := rig.do(http.StatusOK).Header().Get("Retry-After"); got != "31" {
		t.Errorf("Retry-After with 30.5s left = %q, want \"31\": rounded down, a "+
			"client honouring it arrives while the circuit is still open", got)
	}
	rig.clock.Advance(30 * time.Second)
	if got := rig.do(http.StatusOK).Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After with half a second left = %q, want \"1\": rounded up, "+
			"never zero, which tells a client to retry at once", got)
	}
}

// TestStreamingProbeSettlesOnItsStatus: the probe's verdict is its status, and
// a stream or websocket has its status long before it ends. Settling when the
// handler returned would hold the circuit half-open -- refusing every other
// caller -- for as long as the probe's connection stayed up.
func TestStreamingProbeSettlesOnItsStatus(t *testing.T) {
	rig := newBreakerRig(t, quickBreaker())
	rig.open()

	rig.clock.Advance(31 * time.Second)
	stream := rig.park(http.StatusOK, "X-Stream")
	if code := rig.do(http.StatusOK).Code; code != http.StatusOK {
		t.Fatalf("while a probe that answered 200 was still streaming, a request answered %d, "+
			"want 200: the circuit should have closed when the probe's status was written", code)
	}
	rig.finish(stream)
}

// TestPanickingProbeFreesTheProbeSlot: a probe that panics (ReverseProxy
// aborts a response that way) never reports a status. If it kept the probe
// slot, the circuit would stay half-open and refuse every request for good.
func TestPanickingProbeFreesTheProbeSlot(t *testing.T) {
	rig := newBreakerRig(t, quickBreaker())
	rig.open()

	rig.clock.Advance(31 * time.Second)
	func() {
		defer func() { _ = recover() }()
		rig.h.ServeHTTP(httptest.NewRecorder(), rig.request(http.StatusOK, "X-Panic"))
	}()
	if code := rig.do(http.StatusOK).Code; code != http.StatusOK {
		t.Fatalf("after a probe panicked, the next request answered %d, want 200 as "+
			"the next probe", code)
	}
}

// TestCircuitBreakerRefusesSettingsItCannotHonour: an error_threshold of 1.5
// can never be reached and one of -0.1 is always reached, so either switches
// the breaker off or pins it open while the config reads as a breaker.
func TestCircuitBreakerRefusesSettingsItCannotHonour(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	for _, tc := range []struct{ key, value string }{
		{"error_threshold", "1.5"},
		{"error_threshold", "0"},
		{"error_threshold", "-0.1"},
		{"error_threshold", "NaN"},
		{"min_requests", "0"},
		{"min_requests", "-5"},
		{"window_size", "-10s"},
		{"window_size", "0s"},
		{"sleep_window", "-1s"},
	} {
		m := &gateonv1.Middleware{Type: "circuit_breaker", Config: map[string]string{tc.key: tc.value}}
		_, err := f.Create(m, t.Name())
		if err == nil {
			t.Errorf("%s=%q was accepted", tc.key, tc.value)
			continue
		}
		if !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s=%q refused with %q, which does not name the setting", tc.key, tc.value, err)
		}
	}
	m := &gateonv1.Middleware{Type: "circuit_breaker", Config: map[string]string{
		"error_threshold": "1", "min_requests": "1", "window_size": "1s", "sleep_window": "1s",
	}}
	if _, err := f.Create(m, t.Name()); err != nil {
		t.Errorf("boundary values refused: %v", err)
	}
}

// TestHijackedProbeClosesTheCircuit is the websocket case of the streaming
// probe: the proxy hijacks the client connection only after the backend has
// agreed to switch protocols, so a successful hijack is the probe's answer.
func TestHijackedProbeClosesTheCircuit(t *testing.T) {
	clock := newBreakerClock()
	cfg := quickBreaker()
	cfg.RouteID, cfg.now = t.Name(), clock.Now
	release := make(chan struct{})
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			code, _ := strconv.Atoi(r.Header.Get("X-Status"))
			w.WriteHeader(code)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack through the breaker: %v", err)
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: test\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		<-release
	})
	srv := httptest.NewServer(CircuitBreaker(cfg)(backend))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	get := func(status int) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		req.Header.Set("X-Status", strconv.Itoa(status))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	clock.Advance(11 * time.Second)
	get(http.StatusInternalServerError)
	if code := get(http.StatusOK); code != http.StatusServiceUnavailable {
		t.Fatalf("circuit did not open: %d", code)
	}

	clock.Advance(31 * time.Second)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: probe\r\nUpgrade: test\r\nConnection: Upgrade\r\n\r\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, " 101 ") {
		t.Fatalf("probe upgrade answered %q (%v), want 101", line, err)
	}
	if code := get(http.StatusOK); code != http.StatusOK {
		t.Fatalf("while the probe's upgraded connection was open a request answered %d, "+
			"want 200: the upgrade was the probe's answer", code)
	}
}

func breakerGauge(t *testing.T, route string) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() { telemetry.CircuitBreakerState.Collect(ch); close(ch) }()
	got := map[string]float64{}
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatalf("read gauge: %v", err)
		}
		labels := map[string]string{}
		for _, l := range d.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		if labels["route"] == route {
			got[labels["state"]] = d.GetGauge().GetValue()
		}
	}
	return got
}

// TestBreakerPublishesItsState: the dashboard's open and half-open tiles are
// summed from gateon_circuit_breaker_state, which nothing registered, so they
// read zero whatever the breakers were doing.
func TestBreakerPublishesItsState(t *testing.T) {
	rig := newBreakerRig(t, quickBreaker())
	route := t.Name()
	expect := func(state string) {
		t.Helper()
		want := map[string]float64{"closed": 0, "open": 0, "half-open": 0}
		want[state] = 1
		if got := breakerGauge(t, route); !maps.Equal(got, want) {
			t.Fatalf("gauge = %v, want %v", got, want)
		}
	}
	expect("closed")
	rig.open()
	expect("open")
	rig.clock.Advance(31 * time.Second)
	probe := rig.park(http.StatusOK, "X-Hold")
	expect("half-open")
	rig.finish(probe)
	expect("closed")
}

// TestRetainCircuitBreakersForgetsDeletedRoutes: breaker state lives in a
// process-wide map keyed by route label. A deleted route's entry, and its
// gauge, stayed until restart -- so a route deleted while its circuit was open
// counted as an open circuit on the dashboard forever.
func TestRetainCircuitBreakersForgetsDeletedRoutes(t *testing.T) {
	rig := newBreakerRig(t, quickBreaker())
	rig.open()

	live := map[string]bool{}
	cbMu.Lock()
	for route := range cbStates {
		live[route] = route != t.Name()
	}
	cbMu.Unlock()
	RetainCircuitBreakers(live)

	cbMu.Lock()
	_, kept := cbStates[t.Name()]
	cbMu.Unlock()
	if kept {
		t.Error("breaker state of a route not in the live set was kept")
	}
	if got := breakerGauge(t, t.Name()); len(got) != 0 {
		t.Errorf("gauge series of a forgotten breaker = %v, want none", got)
	}
	for route, isLive := range live {
		if !isLive {
			continue
		}
		cbMu.Lock()
		_, ok := cbStates[route]
		cbMu.Unlock()
		if !ok {
			t.Errorf("live route %q lost its breaker", route)
		}
	}
}

// TestRecoveredCircuitIsJudgedOnItsOwnRequests: requests admitted before the
// circuit opened can finish after it has closed again. Counted, they would
// judge the recovered backend on the outage it recovered from. The window is
// longer than the sleep window here so that nothing but the phase check and
// the reset on each transition keeps the old counts out.
func TestRecoveredCircuitIsJudgedOnItsOwnRequests(t *testing.T) {
	rig := newBreakerRig(t, CircuitBreakerConfig{
		MinRequests: 2, ErrorThreshold: 0.6, WindowSize: time.Minute, SleepWindow: 30 * time.Second,
	})
	stale := []<-chan *httptest.ResponseRecorder{
		rig.park(http.StatusInternalServerError, "X-Hold"),
		rig.park(http.StatusInternalServerError, "X-Hold"),
	}
	rig.do(http.StatusInternalServerError)
	rig.do(http.StatusInternalServerError)
	if code := rig.do(http.StatusOK).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("after 2 failures in 2 requests a request answered %d, want 503", code)
	}
	rig.clock.Advance(31 * time.Second)
	if code := rig.do(http.StatusOK).Code; code != http.StatusOK {
		t.Fatalf("probe answered %d, want 200", code)
	}

	for range stale {
		rig.backend.release <- struct{}{}
	}
	for _, done := range stale {
		<-done
	}
	// One failure in two requests is under the 0.6 threshold. With the two
	// stale failures and the two that tripped the circuit counted, it is 5 in 6.
	rig.do(http.StatusOK)
	rig.do(http.StatusInternalServerError)
	if code := rig.do(http.StatusOK).Code; code != http.StatusOK {
		t.Fatalf("after 1 failure in 2 requests since recovery a request answered %d, "+
			"want 200: failures from before the circuit opened were counted", code)
	}
}
