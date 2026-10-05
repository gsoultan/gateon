// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// gaugeValue reads g's current value.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("read gauge: %v", err)
	}
	return m.GetGauge().GetValue()
}

// TestForgedAnswersDoNotLowerTheUnverifiedGauge is DP-N6. The gauge of
// clients held at the challenge was decremented as soon as an answer arrived,
// before it was checked, so 1000 forged answers took it to -1000 and an
// operator watching it saw the bots they were challenging as "verified".
func TestForgedAnswersDoNotLowerTheUnverifiedGauge(t *testing.T) {
	h, _ := botRoute(t)
	before := gaugeValue(t, telemetry.ActiveUnverifiedClientsTotal)
	for i := range 200 {
		req := botRequest(http.MethodGet, "/", botUA)
		req.Header.Set(HeaderChallenge, challengeAnswer)
		req.Header.Set(HeaderChallengeID, strconv.Itoa(i)+".deadbeef")
		req.Header.Set(HeaderChallengeNonce, "1")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if after := gaugeValue(t, telemetry.ActiveUnverifiedClientsTotal); after != before {
		t.Fatalf("200 forged answers moved the unverified-clients gauge from %v to %v", before, after)
	}
}

// TestAVerifiedAnswerLowersTheGauge: the decrement still happens, once, for
// an answer that does the work.
func TestAVerifiedAnswerLowersTheGauge(t *testing.T) {
	h, _ := botRoute(t)
	served := httptest.NewRecorder()
	h.ServeHTTP(served, botRequest(http.MethodGet, "/", botUA))
	m := pageChallenge.FindStringSubmatch(served.Body.String())
	if m == nil {
		t.Fatalf("no challenge served: %d", served.Code)
	}
	before := gaugeValue(t, telemetry.ActiveUnverifiedClientsTotal)
	nonce := 0
	for !workDone(m[1], strconv.Itoa(nonce), challengeBits) {
		nonce++
	}
	req := botRequest(http.MethodGet, "/", botUA)
	req.Header.Set(HeaderChallenge, challengeAnswer)
	req.Header.Set(HeaderChallengeID, m[1])
	req.Header.Set(HeaderChallengeNonce, strconv.Itoa(nonce))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("a solved answer got %d, want 204", rec.Code)
	}
	if after := gaugeValue(t, telemetry.ActiveUnverifiedClientsTotal); after != before-1 {
		t.Fatalf("a verified answer moved the gauge from %v to %v, want one lower", before, after)
	}
}

// TestTheUnverifiedCountNeverGoesNegative: a verified answer to a challenge
// another instance served, or one served before a restart, finds nothing to
// take away here.
func TestTheUnverifiedCountNeverGoesNegative(t *testing.T) {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_unverified"})
	c := &unverifiedCount{gauge: g}
	c.verified()
	c.served()
	c.verified()
	c.verified()
	if got := gaugeValue(t, g); got != 0 {
		t.Fatalf("gauge = %v after one challenge and three verified answers, want 0", got)
	}
	c.served()
	if got := gaugeValue(t, g); got != 1 {
		t.Fatalf("gauge = %v after the floor, want 1", got)
	}
}
