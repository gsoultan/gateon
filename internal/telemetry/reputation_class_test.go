// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// A reputation score is recorded under repid.For(fingerprint, network) and
// enforced against the same, and since ADR 0024 the fingerprint's class leaves
// out the bits of JA4H a client varies per request. These pin that from the
// telemetry side: the fingerprint the gateway composes (GenerateJA4H, JA4+), the
// store that records a threat's penalty, and the release that finds it again.
// repid cuts the class out of GenerateJA4H's layout, so a change to that layout
// that repid did not follow fails here.

// enteredRequest is a request as the entrypoint hands it on: the state carries
// the TLS fingerprint (empty for plaintext) and the JA4H and JA4+ of this
// request's headers.
func enteredRequest(ip, method, ja4 string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(method, "/account", nil)
	req.RemoteAddr = ip + ":40000"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	ja4h := telemetry.GenerateJA4H(req)
	rs := &request.RequestState{JA4: ja4, JA4H: ja4h, JA4Plus: ja4 + "_" + ja4h}
	return req.WithContext(request.WithState(req.Context(), rs))
}

var browserHeaders = map[string]string{
	"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0",
	"Accept-Language": "en-US",
	"Referer":         "https://shop.example/cart",
}

// TestReputationIdentityFollowsTheJA4HLayout: requests that differ only in what
// a browser varies per request resolve to one identity; requests that differ in
// what separates client software do not.
func TestReputationIdentityFollowsTheJA4HLayout(t *testing.T) {
	const ip = "192.0.2.40"
	base := telemetry.GetReputationID(enteredRequest(ip, http.MethodGet, "", browserHeaders))

	same := map[string]*http.Request{
		"POST":        enteredRequest(ip, http.MethodPost, "", browserHeaders),
		"a cookie":    enteredRequest(ip, http.MethodGet, "", with(browserHeaders, "Cookie", "sid=1")),
		"no referer":  enteredRequest(ip, http.MethodGet, "", with(browserHeaders, "Referer", "")),
		"OPTIONS, no": enteredRequest(ip, http.MethodOptions, "", with(browserHeaders, "Referer", "")),
	}
	for what, req := range same {
		if got := telemetry.GetReputationID(req); got != base {
			t.Errorf("the same client with %s resolves to %q, not %q", what, got, base)
		}
	}
	noLanguage := enteredRequest(ip, http.MethodGet, "", with(browserHeaders, "Accept-Language", ""))
	if telemetry.GetReputationID(noLanguage) == base {
		t.Error("a plaintext client without Accept-Language shares the browser's identity: the class " +
			"lost the header mask that tells a browser from curl")
	}
}

// TestAScoreRecordedFromOneRequestIsReadForTheNext is the whole loop: a threat
// recorded from one of a client's requests, through the store's own penalty,
// lowers the score the blocker reads for that client's next request, whatever
// the next request toggles.
func TestAScoreRecordedFromOneRequestIsReadForTheNext(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "reputation-class.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	for name, ja4 := range map[string]string{"plaintext": "", "tls": "t13d1516h2_8daaf6152771_b0da82dd1658"} {
		t.Run(name, func(t *testing.T) {
			ip := map[string]string{"plaintext": "192.0.2.41", "tls": "192.0.2.42"}[name]
			offending := enteredRequest(ip, http.MethodGet, ja4, browserHeaders)
			next := enteredRequest(ip, http.MethodPost, ja4, with(with(browserHeaders, "Referer", ""), "Cookie", "sid=1"))
			id := telemetry.GetReputationID(next)
			t.Cleanup(func() { telemetry.ResetReputation(id) })

			telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(offending, telemetry.SecurityThreat{
				Type: "waf_blocked", SourceIP: ip, Score: 100, Time: time.Now(),
				Category: "waf", Severity: "high", ActionTaken: telemetry.ActionBlocked,
			}))
			telemetry.FlushThreats()

			if got := telemetry.GetReputationScore(id); got >= 100 {
				t.Errorf("the threat recorded from the client's GET left the score read for its "+
					"next request (%s) at %v: the recording path and the blocker disagree on who "+
					"the client is", id, got)
			}
		})
	}
}

// TestReleasingAFingerprintResetsEveryVariantOfIt: an operator releases the
// fingerprint a threat recorded, which is the whole JA4+ of that one request.
// The client's score is kept for its class, so the release has to find it from
// any variant -- including one that differs in the bits the class leaves out.
func TestReleasingAFingerprintResetsEveryVariantOfIt(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	const ja4 = "t13d1516h2_8daaf6152771_b0da82dd1658"
	recorded := ja4 + "_ge11cr0200_7e33b58890ac"
	released := ja4 + "_po11nn0200_7e33b58890ac"

	ids := []string{repid.For(recorded, "192.0.2.43"), repid.For(recorded, "198.51.100.43")}
	for _, id := range ids {
		telemetry.DecreaseReputation(id, 99, "test: release by class")
		t.Cleanup(func() { telemetry.ResetReputation(id) })
	}

	if n := telemetry.ResetReputationClass(released); n != len(ids) {
		t.Errorf("releasing %q reset %d scores, want %d: the release compares the fingerprint as "+
			"written with the class the scores are kept for", released, n, len(ids))
	}
	for _, id := range ids {
		if got := telemetry.GetReputationScore(id); got < 100 {
			t.Errorf("after the release %s still scores %v", id, got)
		}
	}
}

// with returns a copy of h with key set to v, or removed when v is empty.
func with(h map[string]string, key, v string) map[string]string {
	out := make(map[string]string, len(h)+1)
	for k, val := range h {
		out[k] = val
	}
	if v == "" {
		delete(out, key)
	} else {
		out[key] = v
	}
	return out
}
