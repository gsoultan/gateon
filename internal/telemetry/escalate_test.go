// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"testing"
)

// escalateMitigation was lifted out of processThreat, and its entry guard was
// inverted in the process: the original entered on
//
//	(Mitigated || Category=="reputation" || Score>=80) && Type is not a mitigation
//
// and this now returns early on the negation. An inverted compound condition is
// the kind of change that compiles, passes everything, and quietly either
// mitigates actors it should not or stops mitigating the ones it should — so
// the truth table is pinned here rather than assumed.

func escalationSubject(t *testing.T, mutate func(*SecurityThreat)) *SecurityThreat {
	t.Helper()
	st := &SecurityThreat{
		Type:        "waf_block",
		Category:    "waf",
		SourceIP:    "203.0.113.7",
		Fingerprint: "ja4-" + t.Name(),
		Score:       10,
	}
	mutate(st)
	return st
}

// ipFingerprintCount reports how many distinct fingerprints have been recorded
// against ip, which is the observable side effect of escalation running.
func ipFingerprintCount(ip string) int {
	ipMaliciousMu.Lock()
	defer ipMaliciousMu.Unlock()
	val, _ := ipMaliciousFingerprints.Get(ip)
	fps, _ := val.(map[string]struct{})
	return len(fps)
}

func TestEscalateMitigationEntryGuard(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*SecurityThreat)
		wantRecord bool
	}{
		{
			name:       "mitigated threat escalates",
			mutate:     func(st *SecurityThreat) { st.Mitigated = true },
			wantRecord: true,
		},
		{
			name:       "reputation category escalates even when not mitigated",
			mutate:     func(st *SecurityThreat) { st.Category = "reputation" },
			wantRecord: true,
		},
		{
			name:       "score at the auto-mitigate threshold escalates",
			mutate:     func(st *SecurityThreat) { st.Score = autoMitigateScore },
			wantRecord: true,
		},
		{
			name:       "score just below the threshold does not",
			mutate:     func(st *SecurityThreat) { st.Score = autoMitigateScore - 1 },
			wantRecord: false,
		},
		{
			name:       "unmitigated low-score threat does not",
			mutate:     func(st *SecurityThreat) {},
			wantRecord: false,
		},
		{
			// Acting on a mitigation record would generate another one.
			name: "mitigation records never escalate",
			mutate: func(st *SecurityThreat) {
				st.Mitigated = true
				st.Type = "ip_mitigation"
			},
			wantRecord: false,
		},
		{
			name: "shunning records never escalate",
			mutate: func(st *SecurityThreat) {
				st.Mitigated = true
				st.Type = "ip_shunning"
			},
			wantRecord: false,
		},
		{
			name: "a threat with no fingerprint records no IP association",
			mutate: func(st *SecurityThreat) {
				st.Mitigated = true
				st.Fingerprint = ""
			},
			wantRecord: false,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := escalationSubject(t, tt.mutate)
			// A distinct IP per case so the shared LRU cannot leak state between
			// subtests.
			st.SourceIP = fmt.Sprintf("198.51.100.%d", i+1)

			escalateMitigation(st)

			got := ipFingerprintCount(st.SourceIP) > 0
			if got != tt.wantRecord {
				t.Errorf("escalation recorded = %v, want %v (mitigated=%v category=%q score=%v type=%q)",
					got, tt.wantRecord, st.Mitigated, st.Category, st.Score, st.Type)
			}
		})
	}
}

// The IP is only shunned once enough distinct fingerprints appear behind it —
// one address can front an entire office, and shunning on the first bad client
// would take out everyone sharing the NAT.
func TestEscalateMitigationAccumulatesFingerprintsPerIP(t *testing.T) {
	const ip = "198.51.100.200"

	for i := range ipShunUniqueUserThreshold {
		escalateMitigation(&SecurityThreat{
			Type:        "waf_block",
			Category:    "waf",
			SourceIP:    ip,
			Fingerprint: fmt.Sprintf("ja4-distinct-%d", i),
			Mitigated:   true,
		})
		if got, want := ipFingerprintCount(ip), i+1; got != want {
			t.Fatalf("after %d threats: %d fingerprints recorded, want %d", i+1, got, want)
		}
	}

	// The same fingerprint again must not inflate the count — the threshold
	// counts distinct actors, not requests.
	escalateMitigation(&SecurityThreat{
		Type:        "waf_block",
		Category:    "waf",
		SourceIP:    ip,
		Fingerprint: "ja4-distinct-0",
		Mitigated:   true,
	})
	if got := ipFingerprintCount(ip); got != ipShunUniqueUserThreshold {
		t.Errorf("repeat fingerprint changed the count to %d, want %d",
			got, ipShunUniqueUserThreshold)
	}
}

// The map stored in the LRU is an interface value; a wrong-typed entry must not
// panic the writer goroutine. The original code used a bare type assertion.
func TestEscalateMitigationSurvivesWrongTypedCacheEntry(t *testing.T) {
	const ip = "198.51.100.250"
	ipMaliciousMu.Lock()
	ipMaliciousFingerprints.Add(ip, "not a fingerprint set")
	ipMaliciousMu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("escalateMitigation panicked on a wrong-typed cache entry: %v", r)
		}
	}()

	escalateMitigation(&SecurityThreat{
		Type:        "waf_block",
		Category:    "waf",
		SourceIP:    ip,
		Fingerprint: "ja4-recovers",
		Mitigated:   true,
	})

	if got := ipFingerprintCount(ip); got != 1 {
		t.Errorf("recovered entry holds %d fingerprints, want 1", got)
	}
}

// The funnel switch became an ordered rule table. Order is load-bearing: the
// original switch was first-match-wins, so a threat categorised "waf" that also
// looks "advanced" counts as WAF. A table that matched in a different order
// would move counts between middlewares and nothing would fail.

func TestMitigationFunnelRulePrecedence(t *testing.T) {
	// Index of the first rule that claims a (category, type) pair.
	firstMatch := func(cat, typ string) int {
		for i, r := range mitigationFunnelRules {
			if r.matches(cat, typ) {
				return i
			}
		}
		return -1
	}

	tests := []struct {
		name string
		cat  string
		typ  string
	}{
		{name: "waf category", cat: "waf", typ: "waf_block"},
		{name: "fast path prefix", cat: "", typ: "fast_path_ipfilter"},
		{name: "rate limit", cat: "abuse", typ: "rate_limit"},
		{name: "deception", cat: "deception", typ: "honeypot_hit"},
		{name: "advanced", cat: "advanced", typ: "reputation_hit"},
		{name: "geoip", cat: "geoip", typ: ""},
		{name: "auth", cat: "auth", typ: typeBruteForce},
		{name: "bot", cat: "bot", typ: ""},
		{name: "file security", cat: "malware", typ: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstMatch(tt.cat, tt.typ); got < 0 {
				t.Errorf("no funnel rule claims cat=%q typ=%q; the threat would be counted nowhere",
					tt.cat, tt.typ)
			}
		})
	}

	// A WAF block that is also advanced must land on the WAF rule, which sits
	// earlier in the table. This is the precedence the switch encoded implicitly.
	wafIdx := firstMatch("waf", "waf_block")
	advIdx := firstMatch("advanced", "reputation_hit")
	if wafIdx >= advIdx {
		t.Errorf("WAF rule at %d must precede advanced-security at %d", wafIdx, advIdx)
	}
	if got := firstMatch("waf", "reputation_hit"); got != wafIdx {
		t.Errorf("a waf-category threat also matching advanced went to rule %d, want the WAF rule %d",
			got, wafIdx)
	}
}

// An unrecognised threat must fall through every rule rather than being
// attributed to whichever middleware happens to be last.
func TestMitigationFunnelIgnoresUnknownCategories(t *testing.T) {
	for _, r := range mitigationFunnelRules {
		if r.matches("something-nobody-defined", "also-undefined") {
			t.Error("an unrecognised threat matched a funnel rule; counts would be misattributed")
		}
	}
}

// Note on what is deliberately NOT tested here: invoking rule.record would
// increment the real Prometheus counters, and TestMitigationFunnelReconciles
// sums those across every label to check the funnel adds up. A test that fires
// the recorders passes on its own and breaks that one — which is exactly what
// happened when this file first tried it. The matchers are pure and carry the
// dispatch logic that was rewritten; the recorders are one-line counter
// increments already covered by the reconcile test.
