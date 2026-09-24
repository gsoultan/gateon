// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
)

// refusalLogInterval is the least time between two log lines for one refused
// route. The route refuses every request until it is fixed, so a line per
// request would hand anyone who can reach it a way to flood the log.
const refusalLogInterval = 10 * time.Second

// RefusedChain answers for a route whose configured security middleware could
// not be built: it refuses rather than serving a chain missing a control the
// route was configured to have.
//
// It is a named type rather than a closure so the proxy cache can tell a
// refusal from a working chain. A refusal is often the result of something
// briefly unavailable when the chain was built — an identity provider, a
// database file still downloading — and a cache that holds it like any other
// chain keeps the route down until someone edits it.
type RefusedChain struct {
	route   string
	missing string
	builtAt time.Time
	lastLog atomic.Int64 // unix nanoseconds of the last logged refusal
	logf    func(msg string, args ...any)
}

func newRefusedChain(route string, missing []string) *RefusedChain {
	return &RefusedChain{
		route:   route,
		missing: strings.Join(missing, ","),
		builtAt: time.Now(),
		logf:    logger.L.LogError,
	}
}

// BuiltAt is when the refused chain was built, which is what a cache measures
// its retry interval from.
func (c *RefusedChain) BuiltAt() time.Time { return c.builtAt }

func (c *RefusedChain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.logRefusal(r)
	http.Error(w, "Service Unavailable: route configuration incomplete", http.StatusServiceUnavailable)
}

// logRefusal reports a refused request at most once per refusalLogInterval.
func (c *RefusedChain) logRefusal(r *http.Request) {
	now := time.Now().UnixNano()
	last := c.lastLog.Load()
	if last != 0 && now-last < int64(refusalLogInterval) {
		return
	}
	if !c.lastLog.CompareAndSwap(last, now) {
		return
	}
	c.logf("refusing request: route is missing security middleware",
		"route", c.route, "missing", c.missing, "path", r.URL.Path)
}
