// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package deadline decides how long a request may hold a gateway connection,
// and in particular when a response may outlive the deadlines its listener set
// (ADR 0042).
//
// Every HTTP listener sets a read and a write deadline on each request. A
// stream -- a WebSocket tunnel, or a server-sent-event response -- is the one
// response that has to outlive them, and it used to be recognised by a header
// the client wrote: any request carrying Upgrade, or an Accept naming
// text/event-stream, had no deadline at all, on any route. A client chose its
// own timeout. A stream is now recognised by what the server answered -- 101
// from the backend, or a 200 whose Content-Type is text/event-stream -- and
// only then are the request's deadlines replaced, by the two bounds in
// StreamLimits rather than by none.
package deadline

import (
	"os"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
)

// The environment variables that override the tier's stream bounds. Each
// takes a Go duration ("90s", "5m", "4h"); "0" disables that bound.
const (
	IdleTimeoutEnv = "GATEON_STREAM_IDLE_TIMEOUT"
	MaxLifetimeEnv = "GATEON_STREAM_MAX_LIFETIME"
)

// StreamLimits bound a stream once its request's deadlines are lifted. A zero
// field is that bound disabled.
type StreamLimits struct {
	// Idle ends a stream when no byte has moved, in either direction, for
	// this long.
	Idle time.Duration
	// MaxLifetime ends a stream this long after it began, however busy.
	MaxLifetime time.Duration
}

// CurrentStreamLimits is the resource profile's stream bounds
// (config.TierDefaults), each overridden by its environment variable when that
// is set. It reads the environment, so a caller on the request path resolves
// it once, when it is built, rather than per request.
func CurrentStreamLimits() StreamLimits {
	d := config.CurrentTierDefaults()
	return StreamLimits{
		Idle:        envDuration(IdleTimeoutEnv, d.StreamIdleTimeout),
		MaxLifetime: envDuration(MaxLifetimeEnv, d.StreamMaxLifetime),
	}
}

// envDuration is the duration in the environment variable name, or def when
// it is unset, empty or unparseable -- the last said so, since an operator who
// set it meant something. A negative value is 0, the bound disabled.
func envDuration(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		logger.L.LogWarn("ignoring an unparseable stream bound; using the profile default",
			"env", name, "value", v, "default", def.String())
		return def
	}
	return max(d, 0)
}

// endAt is when a stream that began at start, and last moved a byte at last,
// is over: whichever bound comes first. The zero time is no bound at all.
func (l StreamLimits) endAt(start, last time.Time) time.Time {
	var end time.Time
	if l.Idle > 0 {
		end = last.Add(l.Idle)
	}
	if l.MaxLifetime > 0 {
		if life := start.Add(l.MaxLifetime); end.IsZero() || life.Before(end) {
			end = life
		}
	}
	return end
}
