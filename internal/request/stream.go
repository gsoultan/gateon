// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import "net/http"

// StreamMode is a route's answer to which of its responses are streams: lifted
// off the entrypoint's read and write timeouts and bounded instead by the
// stream idle timeout and maximum lifetime (ADR 0042, ADR 0064). It mirrors
// gateon.v1.Route.StreamMode, which this package cannot import.
type StreamMode uint8

const (
	// StreamAuto: a 200 whose Content-Type is text/event-stream and that
	// declares no Content-Length (ADR 0062). The default.
	StreamAuto StreamMode = iota
	// StreamAlways: every response, once its status is written.
	StreamAlways
	// StreamNever: no response; the entrypoint's timeouts bound them all.
	StreamNever
)

// StreamControl is the listener's stream decision, which the route a request
// matched may set before the response begins.
type StreamControl interface {
	SetStreamMode(StreamMode)
}

// FindStreamControl returns the StreamControl w is, or wraps through Unwrap,
// or nil when there is none. Called once per request, at the entrypoint,
// before any middleware has wrapped the writer.
func FindStreamControl(w http.ResponseWriter) StreamControl {
	for w != nil {
		if c, ok := w.(StreamControl); ok {
			return c
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return nil
		}
		w = u.Unwrap()
	}
	return nil
}
