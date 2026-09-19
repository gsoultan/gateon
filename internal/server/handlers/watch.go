// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/telemetry"
	"google.golang.org/protobuf/proto"
)

// WatchEvent represents a multiplexed event sent over the shared SSE connection.
type WatchEvent struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// watchSources bundles the live feeds one /v1/watch connection multiplexes.
type watchSources struct {
	audit   <-chan audit.AuditEntry
	threat  <-chan telemetry.SecurityThreat
	metrics <-chan *telemetry.MetricsSnapshot
	initial *telemetry.MetricsSnapshot
}

// forwardWatchEvents multiplexes src onto out until ctx is done.
//
// Every send selects on ctx as well as on out. The reader is the handler's
// write loop, which returns the moment the client goes away, and nothing drains
// out after that; a bare send that was blocked on a full buffer at that point
// blocked forever, leaking this goroutine and up to twenty buffered events for
// every dropped connection. A source that has been closed -- the handler
// unsubscribes on its way out -- ends the loop for the same reason.
func forwardWatchEvents(ctx context.Context, src watchSources, out chan<- WatchEvent) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	send := func(ev WatchEvent) bool {
		select {
		case out <- ev:
			return true
		case <-ctx.Done():
			return false
		}
	}

	// Send initial metrics if available
	if src.initial != nil && !send(WatchEvent{Type: "metrics", Data: src.initial}) {
		return
	}

	for {
		var ev WatchEvent
		select {
		case <-ctx.Done():
			return
		case log, ok := <-src.audit:
			if !ok {
				return
			}
			ev = WatchEvent{Type: "audit", Data: log}
		case threat, ok := <-src.threat:
			if !ok {
				return
			}
			ev = WatchEvent{Type: "threat", Data: threat}
		case snap, ok := <-src.metrics:
			if !ok {
				return
			}
			ev = WatchEvent{Type: "metrics", Data: snap}
		case <-ticker.C:
			ev = WatchEvent{Type: "heartbeat", Data: time.Now().Unix()}
		}
		if !send(ev) {
			return
		}
	}
}

// RegisterWatchHandler wires the multiplexed real-time event stream.
func RegisterWatchHandler(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/watch", func(w http.ResponseWriter, r *http.Request) {
		// Basic check for diagnostics read permission
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}

		SetSSEHeaders(w)
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Subscribe to multiple broadcasters
		auditCh := audit.Subscribe()
		defer audit.Unsubscribe(auditCh)

		threatCh := telemetry.ThreatBroadcaster.Subscribe()
		defer telemetry.ThreatBroadcaster.Unsubscribe(threatCh)

		metricsCh := telemetry.MetricsBroadcaster.Subscribe()
		defer telemetry.MetricsBroadcaster.Unsubscribe(metricsCh)

		// Create a common channel for all events
		eventCh := make(chan WatchEvent, 20)

		go forwardWatchEvents(r.Context(), watchSources{
			audit:   auditCh,
			threat:  threatCh,
			metrics: metricsCh,
			initial: telemetry.GetLastSnapshot(),
		}, eventCh)

		for {
			select {
			case <-r.Context().Done():
				return
			case ev := <-eventCh:
				if ev.Type == "heartbeat" {
					_, _ = w.Write([]byte(": heartbeat\n\n"))
				} else {
					_, _ = w.Write([]byte("data: "))
					var jsonData []byte
					if msg, ok := ev.Data.(proto.Message); ok {
						// Protobuf message: use protojson for camelCase
						data, _ := ProtojsonOptions().Marshal(msg)
						jsonData = []byte(`{"type":"` + ev.Type + `","data":` + string(data) + `}`)
					} else {
						// Native struct (like AuditEntry) already has camelCase tags
						jsonData, _ = json.Marshal(ev)
					}
					_, _ = w.Write(jsonData)
					_, _ = w.Write([]byte("\n\n"))
				}
				flusher.Flush()
			}
		}
	})
}
