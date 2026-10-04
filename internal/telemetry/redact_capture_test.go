// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// secretMarker is in every credential value these tests send, and in nothing
// else, so "is any credential left?" is one substring search over the record.
const secretMarker = "S3CRET"

// assertRedacted fails when rec, marshalled the way the store and the webhook
// marshal it, still holds a credential, or lost one of the values that were
// not credentials.
func assertRedacted(t *testing.T, what string, rec any, keep ...string) {
	t.Helper()
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal %s: %v", what, err)
	}
	s := string(raw)
	if strings.Contains(s, secretMarker) {
		t.Errorf("%s still carries a credential:\n%s", what, s)
	}
	for _, k := range keep {
		if !strings.Contains(s, k) {
			t.Errorf("%s lost %q, which is not a credential:\n%s", what, k, s)
		}
	}
}

// A trace is read from the dashboard, kept for days and archived for months.
// It kept the query string as sent -- an API key, an OAuth code -- the Referer
// and a redirect's Location with theirs, and a debugger capture's bodies whole:
// the password of a login form, the access token of the response to it.
func TestATraceIsStoredWithoutTheCredentialsItCarried(t *testing.T) {
	freshStore(t)
	now := time.Now().UTC()
	const id = "trace-redacted"
	referer := "https://app.example/start?token=REF-S3CRET&from=home"

	RecordTraceDetailed(id, "POST /login", "svc", "route-1", 1, now, "200", "/login",
		"203.0.113.9", "fp", "US", "ua/1", http.MethodPost, referer,
		"app.example/login?api_key=QRY-S3CRET&code=CODE-S3CRET&q=visible-param", "", "",
		http.Header{"Referer": {referer}, "Authorization": {"Bearer HDR-S3CRET-0123"}},
		"user=alice&password=BODY-S3CRET",
		http.Header{"Location": {"https://app.example/cb?code=LOC-S3CRET&next=dash"}},
		`{"access_token":"RESP-S3CRET","expires_in":3600}`,
		"", 100, 0, 0, 0, 0)
	FlushTraces()

	got := GetTrace(now, id)
	if got == nil {
		t.Fatal("the trace was not stored")
	}
	assertRedacted(t, "the stored trace", got,
		"q=visible-param", "api_key=[REDACTED]", "from=home", "user=alice", "expires_in", "next=dash")
}

// A threat is persisted, broadcast, shipped to a SIEM, correlated and posted
// to every alert channel, all from the one record the store's loop processes.
// Its headers were redacted there; its request URI, bodies and the query
// strings in its Referer were not.
func TestAThreatReachesTheStoreAndTheAlertsWithoutCredentials(t *testing.T) {
	freshStore(t)
	var mu sync.Mutex
	var alerted []SecurityThreat
	SetAlertingHandler(func(st *SecurityThreat) {
		mu.Lock()
		alerted = append(alerted, *st)
		mu.Unlock()
	})
	t.Cleanup(func() { SetAlertingHandler(nil) })

	r := httptest.NewRequest(http.MethodPost, "/api?access_token=QRY-S3CRET&q=visible-param", nil)
	r.Header.Set("Referer", "https://app.example/?password=REF-S3CRET&tab=2")
	th := RecordSecurityThreatWithJA4(r, SecurityThreat{
		ID: "threat-redacted", Type: "waf_blocked", Category: "waf", SourceIP: "203.0.113.10",
		Score: 10, ActionTaken: ActionBlocked, RequestURI: r.RequestURI,
		Details:      "matched in ARGS:q; client sent password=DTL-S3CRET",
		RequestBody:  `{"user":"bob","secret":"BODY-S3CRET"}`,
		ResponseBody: "Authorization: Bearer RESP-S3CRET-0123",
	})
	RecordSecurityThreat(th)
	FlushThreats()

	stored, err := GetSecurityThreatByID(t.Context(), "threat-redacted")
	if err != nil {
		t.Fatalf("the threat was not stored: %v", err)
	}
	keep := []string{"q=visible-param", "tab=2", `\"user\":\"bob\"`, "matched in ARGS:q"}
	assertRedacted(t, "the stored threat", stored, keep...)

	mu.Lock()
	defer mu.Unlock()
	if len(alerted) != 1 {
		t.Fatalf("%d alerts raised, want 1", len(alerted))
	}
	assertRedacted(t, "the threat the alert channels were handed", alerted[0], keep...)
}

// Referer and Location are URIs, and a header the store keeps by name is
// still a query string the client or the backend wrote.
func TestRedactHeadersMasksCredentialsInURIValuedHeaders(t *testing.T) {
	block := "Referer: https://a.example/p?token=T&q=1\nLocation: /cb?code=C&state=S\nX-Forwarded-Uri: /x?api_key=K"
	want := "Referer: https://a.example/p?token=[REDACTED]&q=1\nLocation: /cb?code=[REDACTED]&state=[REDACTED]\nX-Forwarded-Uri: /x?api_key=[REDACTED]"
	if got := RedactHeaders(block); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}
