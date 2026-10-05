// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/alerting"
	"github.com/gsoultan/gateon/internal/middleware/transform"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The CORS middleware called alerting.HandleThreat itself, on the threat as it
// built it, besides recording it (review 3, F2). Three things were wrong with
// that, and these tests pin each: the copy it alerted on had not been through
// the store's redaction, so a webhook received ?access_token=SECRETVALUE; the
// store hands every threat to the same handler, so the violation was alerted
// twice; and playbook evaluation -- and a block action's database write ran
// on the request path.

// corsSecret is the credential the cross-origin request carries in its query.
const corsSecret = "SECRETVALUE"

// heldDispatcher holds every delivery until released, so a test can count the
// deliveries started before any finishes, then hands it to a real webhook.
type heldDispatcher struct {
	release chan struct{}
	sent    chan telemetry.SecurityThreat
	webhook alerting.Dispatcher
}

func (d *heldDispatcher) Send(ctx context.Context, th telemetry.SecurityThreat) error {
	select {
	case <-d.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	d.sent <- th
	return d.webhook.Send(ctx, th)
}

// alertOnEveryThreat installs an alerting manager with an "All threats"
// playbook at threshold 0 -- cors_violation scores 0 -- whose one dispatcher
// is held, posting to a webhook sink. It returns the dispatcher, the sink's
// payloads and the manager's in-flight count.
func alertOnEveryThreat(t *testing.T) (*heldDispatcher, chan []byte, func() int32) {
	t.Helper()
	payloads := make(chan []byte, 4)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		payloads <- raw
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(sink.Close)

	held := &heldDispatcher{
		release: make(chan struct{}),
		sent:    make(chan telemetry.SecurityThreat, 4),
		webhook: alerting.NewWebhookDispatcher(sink.URL),
	}
	t.Cleanup(func() { close(held.release) }) // after the last read; LIFO
	inFlight := alerting.UseManager(t, &gateonv1.AlertingConfig{
		Enabled: true,
		Playbooks: []*gateonv1.AlertPlaybook{{
			Name: "All threats", EventType: "all", Threshold: 0, DispatcherIds: []string{"hook"},
		}},
	}, map[string]alerting.Dispatcher{"hook": held})
	return held, payloads, inFlight
}

// crossOriginRequest is a GET from a disallowed origin carrying a credential
// in its query string, through a route's CORS middleware.
func crossOriginRequest(t *testing.T) int {
	t.Helper()
	h := transform.CORS(transform.CORSConfig{AllowedOrigins: []string{"https://app.example.com"}})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/api/data?access_token="+corsSecret+"&page=2", nil)
	req.RemoteAddr = "198.51.100.40:5000"
	req.Header.Set("Origin", "https://evil.example.net")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// TestACORSViolationIsNotAlertedOnTheRequestPath: with the threat pipeline's
// alert hook off, nothing may reach the alerting manager. A dispatch the
// request path started is held, so it is still in flight when counted.
func TestACORSViolationIsNotAlertedOnTheRequestPath(t *testing.T) {
	_, _, inFlight := alertOnEveryThreat(t)
	telemetry.SetAlertingHandler(nil)

	if code := crossOriginRequest(t); code != http.StatusOK {
		t.Fatalf("the CORS middleware answered %d; it lets the request through", code)
	}
	if n := inFlight(); n != 0 {
		t.Errorf("the request path started %d alert deliveries; alerts belong to the threat pipeline", n)
	}
}

// TestACORSViolationIsAlertedOnceAndRedacted: through the pipeline, as main
// wires it, the violation is alerted once, and the webhook payload carries the
// redacted query string.
func TestACORSViolationIsAlertedOnceAndRedacted(t *testing.T) {
	held, payloads, inFlight := alertOnEveryThreat(t)
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "cors-alert.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })
	telemetry.SetAlertingHandler(alerting.HandleThreat)
	t.Cleanup(func() { telemetry.SetAlertingHandler(nil) })

	crossOriginRequest(t)
	telemetry.FlushThreats()
	if n := inFlight(); n != 1 {
		t.Fatalf("%d alert deliveries were started for one violation, want 1", n)
	}

	held.release <- struct{}{}
	th := <-held.sent
	if th.Type != "cors_violation" {
		t.Fatalf("alerted on %s, want the cors_violation", th.Type)
	}
	if strings.Contains(th.RequestURI, corsSecret) || !strings.Contains(th.RequestURI, "page=2") {
		t.Errorf("the alerted threat's URI is %q", th.RequestURI)
	}
	payload := string(<-payloads)
	if strings.Contains(payload, corsSecret) {
		t.Errorf("the webhook received the credential: %s", payload)
	}
	if !strings.Contains(payload, "access_token=[REDACTED]") {
		t.Errorf("the webhook payload does not name the masked parameter: %s", payload)
	}
}
