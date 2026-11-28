// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package bypasswatch notices the request that got through after a search
// (ADR 0107).
//
// An attacker that adapts its payload from each answer -- a fuzzer, or a
// language model running a loop -- sends a few requests, reads each refusal,
// and changes the payload. It can stay under every rate threshold and still
// try a hundred variants against one endpoint in an hour. The request worth
// an operator's attention in that search is the one that was *forwarded*
// after many different payloads from the same client on the same endpoint
// were refused: it is the likeliest bypass the WAF has.
//
// The watch remembers, per client address, the endpoints (route, method,
// path) on which it refused that client, and how many distinct payloads it
// refused there. A forwarded request on such an endpoint, once that count
// reaches the threshold, is a finding. It carries the forwarded request with
// every credential removed (the tuning sample's capture, ADR 0097), so the
// operator can read it and turn it into a rule.
//
// A finding is observed and held against nobody (ADR 0059): the request was
// let through, and a person who retypes a form after a false refusal looks
// the same. That case is worth seeing too -- it is a false positive.
//
// Everything is bounded and nothing on the request path waits. A refusal is
// handed over on a channel that drops when full. A forwarded request costs a
// lock-free lookup of its client's address, and only a client with a search
// under way -- an endpoint at the threshold -- hands anything over. One goroutine owns every count, and
// stops with the gateway.
package bypasswatch

import (
	"context"
	"hash/maphash"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/security/waf/corpus"
)

// The environment the process-wide watch is configured from.
const (
	// SourcesEnv overrides how many client addresses are followed at once.
	// 0 turns the watch off.
	SourcesEnv = "GATEON_WAF_BYPASS_SOURCES"
	// RefusalsEnv overrides how many distinct refused payloads on one
	// endpoint make the next forwarded request there a finding.
	RefusalsEnv = "GATEON_WAF_BYPASS_REFUSALS"
)

// Fixed bounds. Each is small enough that the whole watch is
// MaxSources x maxEndpoints x (two short strings and maxHashes words).
const (
	// DefaultRefusals is the threshold when RefusalsEnv does not set one.
	DefaultRefusals = 5
	maxRefusals     = 32

	// maxEndpoints is how many endpoints are followed for one client. A
	// client refused on more is a scanner, not a search, and the oldest
	// endpoint makes room.
	maxEndpoints = 8
	// maxHashes is how many distinct payloads are told apart per endpoint.
	// The threshold cannot exceed it.
	maxHashes = maxRefusals
	// maxPath bounds the path an endpoint is remembered by.
	maxPath = 256
	// idle is how long a client is followed after its last refusal.
	idle = time.Hour
	// queue is how many events may wait for the goroutine.
	queue = 256
)

// Finding is one forwarded request that came after a search.
type Finding struct {
	Source   string // the client's address
	Route    string
	Method   string
	Path     string
	Refusals int // distinct payloads refused on this endpoint before it
	// Request is the forwarded request without its credentials, or nil
	// when it did not fit the capture's bounds.
	Request *corpus.Entry
}

// Config sizes a watch.
type Config struct {
	MaxSources int // 0 is off
	Refusals   int
}

type event struct {
	source string
	ep     endpoint
	hash   uint64        // a refusal's payload
	entry  *corpus.Entry // a forward's capture; nil for a refusal
	at     time.Time
}

type endpoint struct{ route, method, path string }

type endpointState struct {
	ep     endpoint
	hashes []uint64
	last   time.Time
}

type sourceState struct {
	endpoints []*endpointState
	last      time.Time
}

// Watch is one process's search detector. It is safe for concurrent use;
// its counts are owned by the goroutine Run starts.
type Watch struct {
	cfg     Config
	in      chan event
	hot     sync.Map // source address -> struct{}: followed by the goroutine
	sink    atomic.Pointer[func(Finding)]
	seed    maphash.Seed
	dropped atomic.Uint64
	found   atomic.Uint64

	sources map[string]*sourceState // goroutine-owned
}

// New returns a watch sized by cfg. A watch with no sources is off: every
// method does nothing.
func New(cfg Config) *Watch {
	if cfg.Refusals < 2 || cfg.Refusals > maxRefusals {
		cfg.Refusals = DefaultRefusals
	}
	w := &Watch{cfg: cfg, seed: maphash.MakeSeed()}
	if cfg.MaxSources > 0 {
		w.in = make(chan event, queue)
		w.sources = make(map[string]*sourceState)
	}
	return w
}

// FromEnv reads the process's watch from the environment and the tier.
func FromEnv() Config {
	cfg := Config{
		MaxSources: config.CurrentTierDefaults().WAFBypassWatchSources,
		Refusals:   DefaultRefusals,
	}
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(SourcesEnv))); err == nil && n >= 0 {
		cfg.MaxSources = min(n, 65536)
	}
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(RefusalsEnv))); err == nil {
		cfg.Refusals = n
	}
	return cfg
}

// Shared is the process's one watch.
var Shared = sync.OnceValue(func() *Watch { return New(FromEnv()) })

// Enabled reports whether the watch follows anyone.
func (w *Watch) Enabled() bool { return w.in != nil }

// Threshold is how many distinct refused payloads make a finding.
func (w *Watch) Threshold() int { return w.cfg.Refusals }

// SetSink sets what is called with each finding, from the watch's goroutine.
func (w *Watch) SetSink(sink func(Finding)) { w.sink.Store(&sink) }

// Dropped is how many events found the queue full.
func (w *Watch) Dropped() uint64 { return w.dropped.Load() }

// Found is how many findings were made.
func (w *Watch) Found() uint64 { return w.found.Load() }

// Refused records that the WAF refused source's request r on route. payload
// is what tells this refusal's payload from the client's others; equal
// payloads count once, so a retried request is not a search.
func (w *Watch) Refused(r *http.Request, source, route string, payload ...string) {
	if w.in == nil || source == "" {
		return
	}
	var h maphash.Hash
	h.SetSeed(w.seed)
	for _, p := range payload {
		_, _ = h.WriteString(p)
		_ = h.WriteByte(0)
	}
	w.send(event{source: source, ep: endpointOf(r, route), hash: h.Sum64(), at: time.Now()})
}

// Forwarded records that the WAF let source's request r through on route.
// A client the watch is not following costs one lookup and nothing else.
func (w *Watch) Forwarded(r *http.Request, source, route string) {
	if w.in == nil || source == "" {
		return
	}
	if _, followed := w.hot.Load(source); !followed {
		return
	}
	e := event{source: source, ep: endpointOf(r, route), at: time.Now()}
	if entry, ok := corpus.Capture(r, route); ok {
		e.entry = entry
	} else {
		e.entry = &corpus.Entry{Method: r.Method, Target: e.ep.path}
	}
	w.send(e)
}

func (w *Watch) send(e event) {
	select {
	case w.in <- e:
	default:
		w.dropped.Add(1)
	}
}

func endpointOf(r *http.Request, route string) endpoint {
	path := r.URL.EscapedPath()
	if len(path) > maxPath {
		path = path[:maxPath]
	}
	return endpoint{route: route, method: r.Method, path: path}
}

// Run applies events until ctx is done. It is the only goroutine that reads
// or writes the counts, and returns at once on a watch that is off.
func (w *Watch) Run(ctx context.Context) {
	if w.in == nil {
		return
	}
	sweep := time.NewTicker(idle / 4)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-w.in:
			w.apply(e)
		case now := <-sweep.C:
			w.forgetIdle(now)
		}
	}
}

// Drain applies the events waiting now, on the caller's goroutine. It is for
// a process that does not call Run -- a test, or a tool -- and must not be
// called while Run is running.
func (w *Watch) Drain() {
	for len(w.in) > 0 {
		w.apply(<-w.in)
	}
}

func (w *Watch) apply(e event) {
	if e.entry == nil {
		w.refused(e)
		return
	}
	w.forwarded(e)
}

func (w *Watch) refused(e event) {
	src := w.sources[e.source]
	if src == nil {
		if len(w.sources) >= w.cfg.MaxSources && !w.evictOldest() {
			return
		}
		src = &sourceState{}
		w.sources[e.source] = src
	}
	src.last = e.at
	st := src.endpoint(e.ep, e.at)
	st.last = e.at
	for _, h := range st.hashes {
		if h == e.hash {
			return
		}
	}
	if len(st.hashes) < maxHashes {
		st.hashes = append(st.hashes, e.hash)
	}
	// Only a client with a search under way is looked at when it is let
	// through. One refused once -- most often a person, after a false
	// positive -- costs its later requests nothing.
	if len(st.hashes) == w.cfg.Refusals {
		w.hot.Store(e.source, struct{}{})
	}
}

func (w *Watch) forwarded(e event) {
	src := w.sources[e.source]
	if src == nil {
		return
	}
	for i, st := range src.endpoints {
		if st.ep != e.ep || len(st.hashes) < w.cfg.Refusals {
			continue
		}
		w.found.Add(1)
		if sink := w.sink.Load(); sink != nil {
			(*sink)(Finding{
				Source: e.source, Route: e.ep.route, Method: e.ep.method, Path: e.ep.path,
				Refusals: len(st.hashes), Request: e.entry,
			})
		}
		// One finding per search: the endpoint starts again, so a client
		// that keeps getting through is not reported on every request.
		src.endpoints = append(src.endpoints[:i], src.endpoints[i+1:]...)
		if !src.searching(w.cfg.Refusals) {
			w.hot.Delete(e.source)
		}
		return
	}
}

// searching reports whether any endpoint has reached the threshold.
func (s *sourceState) searching(threshold int) bool {
	for _, st := range s.endpoints {
		if len(st.hashes) >= threshold {
			return true
		}
	}
	return false
}

// endpoint returns the state for ep, making room by dropping the endpoint
// refused longest ago.
func (s *sourceState) endpoint(ep endpoint, at time.Time) *endpointState {
	oldest := -1
	for i, st := range s.endpoints {
		if st.ep == ep {
			return st
		}
		if oldest < 0 || st.last.Before(s.endpoints[oldest].last) {
			oldest = i
		}
	}
	st := &endpointState{ep: ep, last: at}
	if len(s.endpoints) >= maxEndpoints {
		s.endpoints[oldest] = st
		return st
	}
	s.endpoints = append(s.endpoints, st)
	return st
}

// evictOldest drops the client refused longest ago, and reports whether
// there was one to drop.
func (w *Watch) evictOldest() bool {
	var (
		oldest string
		at     time.Time
	)
	for src, st := range w.sources {
		if oldest == "" || st.last.Before(at) {
			oldest, at = src, st.last
		}
	}
	if oldest == "" {
		return false
	}
	w.forget(oldest)
	return true
}

func (w *Watch) forgetIdle(now time.Time) {
	for src, st := range w.sources {
		if now.Sub(st.last) > idle {
			w.forget(src)
		}
	}
}

func (w *Watch) forget(src string) {
	delete(w.sources, src)
	w.hot.Delete(src)
}
