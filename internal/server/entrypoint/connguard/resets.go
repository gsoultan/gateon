// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package connguard

import (
	"sync/atomic"
	"time"
)

// Resets counts the streams one HTTP/2 connection's client cancelled, in
// one-second windows, so a connection that resets them faster than any
// browser does can be closed.
//
// net/http bounds how many handlers an HTTP/2 connection runs at once, not
// how fast its client opens and cancels streams. In the 2026-11-13 lab 128
// connections doing that (CVE-2023-44487, "Rapid Reset") opened 16 million
// streams in a minute, took the gateway to 76,848 goroutines and the 2 GB
// host's memory limit, and legitimate requests to five seconds (review D2).
// A browser cancels a stream when a page navigates away, a few at a time.
//
// The zero value counts nothing; Init sets the limit. It is safe for
// concurrent use and allocates nothing, so it can live inside the connection.
type Resets struct {
	limit   int64
	window  atomic.Int64 // the unix second being counted
	count   atomic.Int64
	tripped atomic.Bool
}

// Init sets how many cancelled streams a second the connection may have; 0 or
// less leaves the guard off.
func (r *Resets) Init(perSecond int) { r.limit = int64(perSecond) }

// Note records one cancelled stream at now. It reports true exactly once: on
// the stream that takes the connection over its limit, which is the caller's
// cue to close it.
func (r *Resets) Note(now time.Time) bool {
	if r.limit <= 0 {
		return false
	}
	sec := now.Unix()
	if w := r.window.Load(); w != sec && r.window.CompareAndSwap(w, sec) {
		r.count.Store(0)
	}
	return r.count.Add(1) > r.limit && r.tripped.CompareAndSwap(false, true)
}
