// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package deadline

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
)

// A route's stream_mode decides in place of the response (ADR 0064): always
// lifts what auto would not, never keeps what auto would lift, and a mode set
// after the response began changes nothing.
func TestTheRouteStreamModeDecides(t *testing.T) {
	limits := StreamLimits{Idle: time.Minute}
	ndjson := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
	}
	sse := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
	}
	for _, tc := range []struct {
		name  string
		mode  request.StreamMode
		write func(http.ResponseWriter)
		want  bool
	}{
		{"auto ndjson", request.StreamAuto, ndjson, false},
		{"always ndjson", request.StreamAlways, ndjson, true},
		{"auto sse", request.StreamAuto, sse, true},
		{"never sse", request.StreamNever, sse, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sw := NewStreamWriter(httptest.NewRecorder(), limits)
			defer Release(sw)
			sw.SetStreamMode(tc.mode)
			tc.write(sw)
			if sw.Streaming() != tc.want {
				t.Fatalf("streaming = %v, want %v", sw.Streaming(), tc.want)
			}
		})
	}

	t.Run("too late", func(t *testing.T) {
		sw := NewStreamWriter(httptest.NewRecorder(), limits)
		defer Release(sw)
		sse(sw)
		sw.SetStreamMode(request.StreamNever)
		if !sw.Streaming() {
			t.Fatal("a mode set after the response began undid its decision")
		}
	})

	t.Run("a released writer forgets its mode", func(t *testing.T) {
		sw := NewStreamWriter(httptest.NewRecorder(), limits)
		sw.SetStreamMode(request.StreamAlways)
		Release(sw)
		next := NewStreamWriter(httptest.NewRecorder(), limits)
		defer Release(next)
		ndjson(next)
		if next.Streaming() {
			t.Fatal("a pooled writer carried the last route's mode into the next request")
		}
	})
}
