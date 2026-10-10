// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/router"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// These tests pin ADR 0064's per-route stream switch, through the listener,
// the entrypoint chain and the route chain the router builds. Without it a
// response was a stream only when the backend answered a 200
// text/event-stream with no length: an NDJSON or long-poll backend was cut at
// the write deadline, and an operator could not stop an event stream from
// being lifted.

// ndjsonType is a streaming media type the automatic rule does not know.
const ndjsonType = "application/x-ndjson"

// startRouteEP starts an entrypoint whose base handler is the route chain the
// router builds for a route with stream_mode mode in front of backend.
func startRouteEP(t *testing.T, mode gateonv1.Route_StreamMode, backend http.Handler) string {
	t.Helper()
	dir := t.TempDir()
	rt := &gateonv1.Route{Id: "stream-route", Name: "stream-route", Type: "http",
		Rule: "PathPrefix(`/`)", ServiceId: "svc", StreamMode: mode}
	chain := router.ApplyRouteMiddlewares(backend, rt, nil,
		config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json")),
		config.NewGlobalRegistry(filepath.Join(dir, "global.json")), nil, nil)
	return startDeadlineEP(t, chain)
}

// typedStream answers n "data:" lines gap apart under contentType, declaring
// no length, then holds the response open until the request ends when hold
// is set. ended receives when the handler stopped.
func typedStream(contentType string, n int, gap time.Duration, ended chan<- time.Time, hold bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { ended <- time.Now() }()
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		if rc.Flush() != nil {
			return
		}
		tick := time.NewTicker(gap)
		defer tick.Stop()
		for i := range n {
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
			}
			if _, err := fmt.Fprintf(w, "data: {\"n\":%d}\n\n", i); err != nil || rc.Flush() != nil {
				return
			}
		}
		if hold {
			<-r.Context().Done()
		}
	})
}

// TestARouteThatAlwaysStreamsOutlivesTheRequestDeadlines: an NDJSON backend on
// a route set to always stream keeps streaming past the entrypoint's
// deadlines. The same backend on an automatic route is cut at the write
// deadline -- the control, which shows it is the switch that lifts it.
func TestARouteThatAlwaysStreamsOutlivesTheRequestDeadlines(t *testing.T) {
	t.Setenv("GATEON_STREAM_IDLE_TIMEOUT", "5s")
	t.Setenv("GATEON_STREAM_MAX_LIFETIME", "1m")
	const want = 16 // 16 x 60ms is three times the deadline
	for name, client := range streamClients(t) {
		t.Run(name, func(t *testing.T) {
			ended := make(chan time.Time, 1)
			addr := startRouteEP(t, gateonv1.Route_STREAM_MODE_ALWAYS,
				typedStream(ndjsonType, want, 60*time.Millisecond, ended, false))
			if got, _, _ := readEvents(t, client, "http://"+addr+"/feed", nil); got != want {
				t.Fatalf("always: received %d of %d lines: the route's stream was cut at the %v request deadline",
					got, want, epDeadline)
			}
		})
		t.Run(name+"/auto_control", func(t *testing.T) {
			ended := make(chan time.Time, 1)
			addr := startRouteEP(t, gateonv1.Route_STREAM_MODE_AUTO,
				typedStream(ndjsonType, want, 60*time.Millisecond, ended, false))
			if got, _, _ := readEvents(t, client, "http://"+addr+"/feed", nil); got >= want {
				t.Fatalf("auto: received all %d NDJSON lines; the automatic rule lifted a type it does not know", got)
			}
		})
	}
}

// TestARouteThatAlwaysStreamsIsStillEndedOnceIdle: "always" lifts a response
// to the stream bounds, not to none. A stream that goes quiet is closed by
// the idle timeout and its handler ends.
func TestARouteThatAlwaysStreamsIsStillEndedOnceIdle(t *testing.T) {
	const idle = 700 * time.Millisecond
	t.Setenv("GATEON_STREAM_IDLE_TIMEOUT", idle.String())
	t.Setenv("GATEON_STREAM_MAX_LIFETIME", "1m")
	for name, client := range streamClients(t) {
		t.Run(name, func(t *testing.T) {
			ended := make(chan time.Time, 1)
			const want = 8 // 8 x 100ms is past the request deadline
			addr := startRouteEP(t, gateonv1.Route_STREAM_MODE_ALWAYS,
				typedStream(ndjsonType, want, 100*time.Millisecond, ended, true))
			got, last, closed := readEvents(t, client, "http://"+addr+"/feed", nil)
			if got != want {
				t.Fatalf("received %d of %d lines before the stream went quiet", got, want)
			}
			if !closed {
				t.Fatalf("the stream was still open %v after it went quiet: always meant no timeout", streamTestBound)
			}
			if quiet := time.Since(last); quiet < idle/2 {
				t.Fatalf("the stream closed %v after its last line, well inside the %v idle timeout", quiet, idle)
			}
			handlerEnded(t, ended)
		})
	}
}

// TestARouteThatNeverStreamsCutsAnEventStream: on a route set to never
// stream, a real event stream -- a 200 text/event-stream with no length, which
// the automatic rule lifts (TestAnEventStreamOutlivesTheRequestDeadlines) --
// keeps the entrypoint's deadlines and is cut at the write deadline.
func TestARouteThatNeverStreamsCutsAnEventStream(t *testing.T) {
	t.Setenv("GATEON_STREAM_IDLE_TIMEOUT", "5s")
	t.Setenv("GATEON_STREAM_MAX_LIFETIME", "1m")
	const want = 16
	for name, client := range streamClients(t) {
		t.Run(name, func(t *testing.T) {
			ended := make(chan time.Time, 1)
			addr := startRouteEP(t, gateonv1.Route_STREAM_MODE_NEVER,
				typedStream("text/event-stream", want, 60*time.Millisecond, ended, false))
			got, _, _ := readEvents(t, client, "http://"+addr+"/events", http.Header{"Accept": {"text/event-stream"}})
			if got >= want {
				t.Fatalf("received all %d events: a route that never streams was lifted off its %v deadline", got, epDeadline)
			}
			handlerEnded(t, ended)
		})
	}
}

// TestARouteThatAlwaysStreamsKeepsTheDeadlinesWhenNoStreamBoundIsSet: with
// both stream bounds disabled, lifting a response would leave it no deadline
// at all. A per-route switch must not be how a response gets none, so the
// route's responses keep the entrypoint's deadlines.
func TestARouteThatAlwaysStreamsKeepsTheDeadlinesWhenNoStreamBoundIsSet(t *testing.T) {
	t.Setenv("GATEON_STREAM_IDLE_TIMEOUT", "0")
	t.Setenv("GATEON_STREAM_MAX_LIFETIME", "0")
	const want = 16
	ended := make(chan time.Time, 1)
	addr := startRouteEP(t, gateonv1.Route_STREAM_MODE_ALWAYS,
		typedStream(ndjsonType, want, 60*time.Millisecond, ended, false))
	got, _, _ := readEvents(t, streamClients(t)["http1"], "http://"+addr+"/feed", nil)
	if got >= want {
		t.Fatalf("received all %d lines with no stream bound set: the response had no deadline at all", got)
	}
	handlerEnded(t, ended)
}
