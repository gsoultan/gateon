// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package scanpool sends files to clamd scanners and reads back their
// verdicts. It is the first step of ADR 0091: one or more scanner addresses
// behind one Scan call, with each scanner's health tracked from what it does.
//
// A Pool starts no goroutine and takes no lock. Health is a few atomics per
// scanner, written by the scans themselves, so there is nothing to shut down
// and nothing on the request path to wait for.
package scanpool

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"time"
)

const (
	// MaxWorkers bounds a pool. Each scanner costs a few words of state; the
	// bound is on how many places a file may be sent, not on memory.
	MaxWorkers = 16
	// faultThreshold is how many faults in a row take a scanner out of
	// rotation. One is a blip; two is a scanner that is not there.
	faultThreshold = 2
	// retryAfter is how long an unhealthy scanner is passed over before a
	// scan is allowed to try it again.
	retryAfter = 10 * time.Second
)

// ErrNoScanners is returned by New for an empty list.
var ErrNoScanners = errors.New("no scanner address configured")

// worker is one scanner and what the pool has seen of it.
type worker struct {
	addr     string
	endpoint endpoint
	inFlight atomic.Int64
	faults   atomic.Int32
	// passOverUntil is a UnixNano before which the worker is unhealthy, or
	// zero when it is healthy.
	passOverUntil atomic.Int64
}

func (w *worker) healthy(now time.Time) bool {
	return now.UnixNano() >= w.passOverUntil.Load()
}

func (w *worker) succeeded() {
	w.faults.Store(0)
	w.passOverUntil.Store(0)
}

func (w *worker) faulted(now time.Time) {
	if w.faults.Add(1) >= faultThreshold {
		w.passOverUntil.Store(now.Add(retryAfter).UnixNano())
	}
}

// Pool is a fixed set of scanners. It is safe for concurrent use.
type Pool struct {
	workers []*worker
	now     func() time.Time
}

// New builds a pool over addrs, each "tcp://host:port" or "unix:///path".
func New(addrs []string) (*Pool, error) {
	if len(addrs) == 0 {
		return nil, ErrNoScanners
	}
	if len(addrs) > MaxWorkers {
		return nil, fmt.Errorf("%d scanner addresses; at most %d are allowed", len(addrs), MaxWorkers)
	}
	p := &Pool{now: time.Now, workers: make([]*worker, 0, len(addrs))}
	for _, addr := range addrs {
		ep, err := parseEndpoint(addr)
		if err != nil {
			return nil, err
		}
		p.workers = append(p.workers, &worker{addr: addr, endpoint: ep})
	}
	return p, nil
}

// pick returns the scanner to try: the healthy one with the fewest scans in
// flight. When none is healthy it returns the one that has been unhealthy
// longest, because a pool that refuses to try is a pool that cannot notice a
// scanner has come back. skip is a worker already tried for this file.
func (p *Pool) pick(now time.Time, skip *worker) *worker {
	var best, stalest *worker
	bestLoad, stalestUntil := int64(math.MaxInt64), int64(math.MaxInt64)
	for _, w := range p.workers {
		if w == skip {
			continue
		}
		if until := w.passOverUntil.Load(); now.UnixNano() < until {
			if until < stalestUntil {
				stalest, stalestUntil = w, until
			}
			continue
		}
		if load := w.inFlight.Load(); load < bestLoad {
			best, bestLoad = w, load
		}
	}
	if best != nil {
		return best
	}
	return stalest
}

// Scan sends content to a scanner and returns its verdict, within timeout.
//
// If the scanner it chose turns out to be at fault -- unreachable, hung up, or
// answering something that is not a verdict -- the file is tried once on
// another, inside the same deadline. Only that kind of failure counts against
// a scanner's health. A scan that ran out of time waiting for a verdict, or
// that clamd answered with an error, does not: how long a file takes and
// whether clamd can read it are things the sender of the file controls, and a
// client must not be able to take a scanner out of rotation by what it
// uploads.
func (p *Pool) Scan(ctx context.Context, content []byte, timeout time.Duration) (Verdict, error) {
	deadline := p.now().Add(timeout)
	first := p.pick(p.now(), nil)
	verdict, err := p.scanOn(ctx, first, content, deadline)
	if err == nil || !errors.Is(err, errWorkerFault) {
		return verdict, err
	}
	second := p.pick(p.now(), first)
	if second == nil || ctx.Err() != nil || !p.now().Before(deadline) {
		return verdict, err
	}
	return p.scanOn(ctx, second, content, deadline)
}

func (p *Pool) scanOn(ctx context.Context, w *worker, content []byte, deadline time.Time) (Verdict, error) {
	w.inFlight.Add(1)
	verdict, err := w.endpoint.scan(ctx, content, deadline)
	w.inFlight.Add(-1)
	switch {
	case err == nil:
		w.succeeded()
	case errors.Is(err, errWorkerFault) && ctx.Err() == nil:
		w.faulted(p.now())
	}
	if err != nil {
		return Verdict{}, fmt.Errorf("scanner %s: %w", w.addr, err)
	}
	return verdict, nil
}

// WorkerStatus is one scanner as the pool currently sees it.
type WorkerStatus struct {
	Addr     string
	Healthy  bool
	InFlight int64
}

// Status reports every scanner, in the order they were configured.
func (p *Pool) Status() []WorkerStatus {
	now := p.now()
	out := make([]WorkerStatus, 0, len(p.workers))
	for _, w := range p.workers {
		out = append(out, WorkerStatus{Addr: w.addr, Healthy: w.healthy(now), InFlight: w.inFlight.Load()})
	}
	return out
}

// Probe pings every scanner once and records the result, so that a scanner
// which accepts connections and never answers -- which no scan can hold
// against it -- is still found. It is for a caller that owns a schedule and a
// lifetime; the pool itself never calls it.
func (p *Pool) Probe(ctx context.Context, timeout time.Duration) {
	for _, w := range p.workers {
		if ctx.Err() != nil {
			return
		}
		if err := w.endpoint.ping(ctx, p.now().Add(timeout)); err != nil {
			w.faulted(p.now())
			continue
		}
		w.succeeded()
	}
}
