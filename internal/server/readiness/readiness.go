// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package readiness holds what /readyz reports beyond the telemetry store: the
// entrypoint listeners that failed to bind, and whether the configuration
// database answers (ADR 0049).
//
// /healthz answers "is the process alive"; /readyz answers "should this
// instance receive traffic". A gateway whose :443 is held by another process,
// or whose user database is down, is alive and must not receive traffic: a
// load balancer that sends it requests gets refusals, and an operator who
// signs in gets told their password is wrong.
package readiness

import (
	"fmt"
	"slices"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// entrypointUp is 1 for an entrypoint whose listeners all bound and 0 for one
// that has a listener that did not. The label is an entrypoint id from the
// gateway's own configuration, so its cardinality is the number of
// entrypoints, not anything a client chooses.
var entrypointUp = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "gateon_entrypoint_up",
	Help: "1 when every listener of the entrypoint is bound, 0 when one failed to bind.",
}, []string{"entrypoint"})

// listeners is every listener a runner reported, keyed by entrypoint and
// address. Written at startup, read by /readyz; bounded by the configuration.
var listeners = struct {
	sync.Mutex
	failed map[listenerKey]string
	bound  map[listenerKey]bool
}{failed: map[listenerKey]string{}, bound: map[listenerKey]bool{}}

type listenerKey struct{ entrypoint, addr string }

// ListenerBound records that a listener of entrypoint is serving addr.
func ListenerBound(entrypoint, addr string) {
	listeners.Lock()
	defer listeners.Unlock()
	k := listenerKey{entrypoint, addr}
	delete(listeners.failed, k)
	listeners.bound[k] = true
	publishLocked(entrypoint)
}

// ListenerFailed records that a listener of entrypoint could not bind addr.
// /readyz answers 503 naming it until ListenerBound says otherwise: the
// entrypoint keeps retrying the bind, with a backoff capped at 30 s, until it
// succeeds or the gateway shuts down (OPS-N5).
func ListenerFailed(entrypoint, addr string, err error) {
	listeners.Lock()
	defer listeners.Unlock()
	k := listenerKey{entrypoint, addr}
	delete(listeners.bound, k)
	listeners.failed[k] = fmt.Sprintf("entrypoint %s could not listen on %s: %v", entrypoint, addr, err)
	publishLocked(entrypoint)
}

// publishLocked sets the gauge for entrypoint from every listener it has.
func publishLocked(entrypoint string) {
	up := 1.0
	for k := range listeners.failed {
		if k.entrypoint == entrypoint {
			up = 0
		}
	}
	entrypointUp.WithLabelValues(entrypoint).Set(up)
}

// listenerReasons is one line per listener that failed to bind, sorted so the
// answer does not change order between probes.
func listenerReasons() []string {
	listeners.Lock()
	out := make([]string, 0, len(listeners.failed))
	for _, r := range listeners.failed {
		out = append(out, r)
	}
	listeners.Unlock()
	slices.Sort(out)
	return out
}

// NotReady lists every reason this instance cannot serve traffic that this
// package knows of: the listeners that failed to bind. Empty means none.
//
// It is deliberately not every fault. A load balancer that health-checks
// /readyz takes a not-ready instance out of rotation, and on the single-node
// target that is an outage; so only a fault that stops this instance serving
// belongs here. One that leaves it serving, degraded, is Degraded's.
func NotReady() []string {
	return listenerReasons()
}

// Degraded lists what is failing on an instance that still serves traffic:
// the configuration database when it does not answer. The data plane keeps
// serving through a database outage by design (ADR 0043 fails block lookups
// open), so taking the instance out of rotation for it would turn a degraded
// gateway into a down one. /readyz reports it in its body and the
// gateon_config_db_up gauge alerts on it.
func Degraded() []string {
	if r := databaseReason(); r != "" {
		return []string{r}
	}
	return nil
}
