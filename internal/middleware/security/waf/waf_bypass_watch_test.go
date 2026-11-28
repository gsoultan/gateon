// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/security/waf/bypasswatch"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestTheRequestThatGotThroughAfterASearchIsRecorded is ADR 0107 end to end:
// a client the WAF refused on one endpoint with five different payloads, and
// then let through there, has that request filed as a suspected bypass --
// observed, and held against nobody.
func TestTheRequestThatGotThroughAfterASearchIsRecorded(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "bypass.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })
	threats := telemetry.ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { telemetry.ThreatBroadcaster.Unsubscribe(threats) })

	mw, err := WAF(WAFConfig{ParanoiaLevel: 1, RouteID: t.Name()})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	h := mw(okOrigin())
	watch := bypasswatch.Shared()
	if !watch.Enabled() {
		t.Fatal("the bypass watch is off on the default tier")
	}

	const attacker = "198.18.7.7"
	sendQuery := func(raw string) int {
		r := httptest.NewRequest(http.MethodGet, "/search?"+raw, nil)
		r.RemoteAddr = attacker + ":40000"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		watch.Drain()
		telemetry.FlushThreats()
		return rr.Code
	}
	send := func(q string) int { return sendQuery("q=" + url.QueryEscape(q)) }
	payloads := []string{
		"<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
		"<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
	}
	for i := 0; i < watch.Threshold(); i++ {
		if code := send(payloads[i%len(payloads)] + strings.Repeat(" ", i)); code != http.StatusForbidden {
			t.Fatalf("payload %d got %d, want refused: the search never happened", i+1, code)
		}
	}
	_ = drainThreats(threats)
	if code := sendQuery("q=shoes&api_key=sk-live-0123456789abcdef"); code != http.StatusOK {
		t.Fatalf("the ordinary request got %d, want it forwarded", code)
	}

	var found *telemetry.SecurityThreat
	for _, th := range drainThreats(threats) {
		if th.Type == telemetry.ThreatWAFEvasionSuspected {
			found = &th
		}
	}
	if found == nil {
		t.Fatal("the request forwarded after the search was not recorded")
	}
	if found.SourceIP != attacker || found.RouteID != t.Name() || !found.Observed {
		t.Errorf("recorded %+v: want the attacker, this route, and observed", *found)
	}
	if !strings.Contains(found.Details, "q=shoes") {
		t.Errorf("the record does not carry the forwarded request: %q", found.Details)
	}
	if strings.Contains(found.Details, "sk-live") {
		t.Errorf("the record carries the request's credential: %q", found.Details)
	}
}

func drainThreats(ch chan telemetry.SecurityThreat) []telemetry.SecurityThreat {
	var out []telemetry.SecurityThreat
	for len(ch) > 0 {
		out = append(out, <-ch)
	}
	return out
}
