// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestWatchThreatEventHasTheThreatListShape pins the frame a live threat
// arrives in.
//
// The dashboard prepends each pushed threat to the list it fetched from
// ListSecurityThreats, which returns the proto Anomaly: source, description,
// httpMethod, ja4plus, and a severity lowercased (or derived from the score)
// to the critical/high/medium/low scale the badges colour by. The stream used
// to push the telemetry struct itself, whose JSON says sourceIp, details,
// method and fingerprint and carries the severity as recorded. Every live row
// therefore rendered with an empty source column and no description until the
// list was refetched, and the trace button on it traced an empty address.
func TestWatchThreatEventHasTheThreatListShape(t *testing.T) {
	threats := make(chan telemetry.SecurityThreat, 1)
	threats <- telemetry.SecurityThreat{
		ID:          "t-1",
		Type:        "waf_block",
		SourceIP:    "203.0.113.9",
		Fingerprint: "t13d1516h2_8daaf6152771_02713d6af862_q1",
		Details:     "SQL injection in parameter q",
		Method:      "POST",
		Severity:    "HIGH",
		Time:        time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC),
	}
	out := make(chan WatchEvent, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		forwardWatchEvents(ctx, watchSources{threat: threats}, out)
	}()
	var ev WatchEvent
	select {
	case ev = <-out:
	case <-time.After(2 * time.Second):
		t.Fatal("the forwarder did not emit the threat")
	}
	cancel()
	<-done

	var frame struct {
		Type string         `json:"type"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(encodeWatchEvent(ev), &frame); err != nil {
		t.Fatalf("frame is not JSON: %v", err)
	}
	if frame.Type != "threat" {
		t.Fatalf("frame type = %q, want threat", frame.Type)
	}
	for field, want := range map[string]string{
		"id":          "t-1",
		"source":      "203.0.113.9",
		"description": "SQL injection in parameter q",
		"httpMethod":  "POST",
		"ja4plus":     "t13d1516h2_8daaf6152771_02713d6af862_q1",
		"severity":    "high",
	} {
		if got, _ := frame.Data[field].(string); got != want {
			t.Errorf("live threat %s = %q, want %q (the list the dashboard merges it into says %q)",
				field, got, want, want)
		}
	}
}

// TestWatchForwarderStopsWhenClientIsGone covers the goroutine behind every
// /v1/watch connection.
//
// It forwards audit, threat and metrics events into a 20-slot channel that the
// handler's write loop drains. That loop returns the moment the request context
// is cancelled -- the client closed the tab, the connection dropped -- and
// nothing drains the channel after that. A forward that was blocked on a full
// channel at that moment blocked forever: a slow client that let twenty events
// pile up and then disconnected leaked the goroutine and every buffered event,
// and each such connection leaked another. Any authenticated dashboard user can
// open and drop as many of these as they like.
//
// An unbuffered channel that nobody reads is that full buffer with the timing
// removed: the very first forward blocks, and the only way out is to notice the
// context.
func TestWatchForwarderStopsWhenClientIsGone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the client is already gone

	unread := make(chan WatchEvent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		forwardWatchEvents(ctx, watchSources{initial: &telemetry.MetricsSnapshot{}}, unread)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("forwarder is still blocked sending to a channel nobody reads after its client left; " +
			"the goroutine and its buffered events leak for every dropped /v1/watch connection")
	}
}
