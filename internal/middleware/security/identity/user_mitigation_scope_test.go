// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// A fingerprint block used to be keyed on the whole JA4+, and a JA4+ names a
// client build, not a client: three WAF blocks from one attacker's stock Chrome
// refused every user of that Chrome build on every network, while the attacker
// shed the block by dropping a Referer, which changes the JA4+ and not the
// browser. ADR 0026 keys it like reputation (ADR 0011, 0024): the part of the
// fingerprint a client cannot vary, on the network it attacked from.

const (
	// A stock browser's JA4+ over TLS, and the same browser's next request,
	// which sent no Referer: same TLS stack, different JA4H.
	chromeJA4Plus          = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"
	chromeNoRefererJA4Plus = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cn0200_7e33b58890ac"
)

// scopeTestStore runs the telemetry store -- its threat loop is what escalates
// evidence to a block -- in a scratch directory.
func scopeTestStore(t *testing.T) {
	t.Helper()
	t.Setenv("GATEON_TRACE_DIR", filepath.Join(t.TempDir(), "traces"))
	_ = telemetry.ClosePathStatsStore(t.Context())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "telemetry.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	telemetry.ResetFingerprintSightings()
	t.Cleanup(func() {
		_ = telemetry.ClosePathStatsStore(t.Context())
		telemetry.ResetFingerprintSightings()
	})
}

// recordThreats records n threats of one kind from a client through the real
// recording path and waits for the store to process them.
func recordThreats(n int, th telemetry.SecurityThreat) {
	for range n {
		telemetry.RecordSecurityThreat(th)
	}
	telemetry.FlushThreats()
}

// wafBlock is a request the WAF refused on its payload: attack evidence.
func wafBlock(fp, ip string) telemetry.SecurityThreat {
	return telemetry.SecurityThreat{
		Type: "waf_blocked", SourceIP: ip, Fingerprint: fp, Score: 100,
		Category: "sqli", Severity: "critical", ActionTaken: telemetry.ActionBlocked,
	}
}

// userMitigationStatus is what UserMitigation answers a client presenting fp
// from ip, as the entrypoint hands the request over.
func userMitigationStatus(fp, ip string) (int, string) {
	h := UserMitigation()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.RemoteAddr = net.JoinHostPort(ip, "41000")
	req = req.WithContext(request.WithState(req.Context(), &request.RequestState{JA4Plus: fp}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code, rr.Body.String()
}

func TestAFingerprintBlockStaysOnTheNetworkThatEarnedIt(t *testing.T) {
	scopeTestStore(t)
	recordThreats(3, wafBlock(chromeJA4Plus, "203.0.113.7"))

	if code, body := userMitigationStatus(chromeJA4Plus, "203.0.113.7"); code != http.StatusForbidden ||
		!strings.Contains(body, "Compromised Fingerprint") {
		t.Fatalf("setup: three WAF blocks did not block the attacker's client build on its network (%d %q)", code, body)
	}
	// The same build elsewhere on the attacker's /24: inside the block.
	if code, _ := userMitigationStatus(chromeJA4Plus, "203.0.113.99"); code != http.StatusForbidden {
		t.Errorf("the attacker's build on the attacker's network got %d, want 403", code)
	}
	// Every other user of that browser build, on every other network.
	for _, ip := range []string{"198.51.100.20", "192.0.2.44", "2001:db8:1:2::9"} {
		if code, _ := userMitigationStatus(chromeJA4Plus, ip); code != http.StatusOK {
			t.Errorf("a bystander on %s running the attacker's browser build got %d; a fingerprint block "+
				"reached a network that never attacked", ip, code)
		}
	}
}

func TestDroppingARefererDoesNotShedAFingerprintBlock(t *testing.T) {
	scopeTestStore(t)
	recordThreats(3, wafBlock(chromeJA4Plus, "203.0.113.7"))

	if code, _ := userMitigationStatus(chromeNoRefererJA4Plus, "203.0.113.7"); code != http.StatusForbidden {
		t.Errorf("the blocked client got %d once it stopped sending a Referer; the block was on "+
			"what the request said, not on the client", code)
	}
}

// An operator's release of a fingerprint holds: the next attack from the class,
// on any network, does not block it again straight away. The Playwright suite
// depends on it -- every spec shares one client build -- and so does an operator
// releasing a false positive.
func TestAReleasedClassIsNotBlockedAgainByTheNextAttack(t *testing.T) {
	scopeTestStore(t)
	recordThreats(3, wafBlock(chromeJA4Plus, "203.0.113.7"))
	if !telemetry.ReleaseUserMitigationClass(chromeJA4Plus) {
		t.Fatal("setup: the release found no block to release")
	}

	for _, ip := range []string{"203.0.113.7", "198.51.100.20"} {
		recordThreats(3, wafBlock(chromeJA4Plus, ip))
		if code, _ := userMitigationStatus(chromeJA4Plus, ip); code != http.StatusOK {
			t.Errorf("three more blocks from %s re-blocked a class the operator had just released (%d)", ip, code)
		}
	}
}

// Rate-limit rejections, bot and geo policy blocks and the blocks that follow
// an earlier decision are what a busy office earns without attacking anyone;
// three of them from one user blocked that office's browser build.
func TestPolicyRefusalsDoNotBlockAClientBuild(t *testing.T) {
	scopeTestStore(t)
	for _, th := range []telemetry.SecurityThreat{
		{Type: "rate_limit", Category: "abuse"},
		{Type: "bot_detected", Category: "bot"},
		{Type: "geoip_block", Category: "geofencing"},
		{Type: "reputation_block", Category: "bot", Score: 100},
	} {
		th.SourceIP, th.Fingerprint, th.ActionTaken = "203.0.113.8", chromeJA4Plus, telemetry.ActionBlocked
		recordThreats(3, th)
		if code, _ := userMitigationStatus(chromeJA4Plus, "203.0.113.8"); code != http.StatusOK {
			t.Errorf("three %s refusals blocked the client build on its network (%d); they are "+
				"policy about the client, not evidence of an attack", th.Type, code)
		}
	}
}
