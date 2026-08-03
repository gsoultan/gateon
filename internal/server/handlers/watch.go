// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package handlers

import (
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

		// Create a common channel for all events
		eventCh := make(chan WatchEvent, 10)

		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-r.Context().Done():
					return
				case log := <-auditCh:
					eventCh <- WatchEvent{Type: "audit", Data: log}
				case threat := <-threatCh:
					eventCh <- WatchEvent{Type: "threat", Data: threat}
				case <-ticker.C:
					eventCh <- WatchEvent{Type: "heartbeat", Data: time.Now().Unix()}
				}
			}
		}()

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
