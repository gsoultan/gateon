// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestTheGenericWebhookPostsNoBodies: the generic webhook posted the whole
// threat record, request and response bodies included, to whatever URL an
// operator configured -- a third party, more often than not. The bodies are
// what a debugger captured from the client and the backend, and nothing on
// the far side of a webhook needs them to raise an alarm: the threat's id,
// type, source and URI say what happened, and the dashboard holds the rest.
// The record keeps its shape, every field present, so a consumer that reads
// requestBody gets an empty string rather than an error.
func TestTheGenericWebhookPostsNoBodies(t *testing.T) {
	got := make(chan map[string]any, 1)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(raw, &payload)
		got <- payload
	}))
	defer sink.Close()

	threat := telemetry.SecurityThreat{
		ID: "t-1", Type: "waf_blocked", SourceIP: "203.0.113.7", RequestURI: "/login?q=1",
		RequestBody:  "user=alice&note=request body text",
		ResponseBody: `{"note":"response body text"}`,
	}
	if err := NewWebhookDispatcher(sink.URL).Send(t.Context(), threat); err != nil {
		t.Fatalf("send: %v", err)
	}
	payload := <-got

	for _, field := range []string{"requestBody", "responseBody"} {
		v, present := payload[field]
		if !present {
			t.Errorf("%s is missing; the payload's shape changed", field)
		}
		if v != "" {
			t.Errorf("%s = %q was posted to the webhook", field, v)
		}
	}
	for field, want := range map[string]string{"id": "t-1", "type": "waf_blocked", "requestUri": "/login?q=1"} {
		if payload[field] != want {
			t.Errorf("%s = %v, want %q", field, payload[field], want)
		}
	}
}
