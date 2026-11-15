// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// These are the parts of the package that decide something on gateon's own
// authority rather than gwaf's: the three resolvers, the two operators the
// eight gateon-defined rules use, and the views of the table other packages
// read. They are what is left here once detection lives in gwaf (ADR 0093), so
// they are what this package's tests have to hold.

// resolvedValues drains a resolver into a map, so a test can tell "said
// nothing" from "said the wrong thing".
func resolvedValues(r rules.Resolver) map[string]string {
	out := map[string]string{}
	for k, v := range r.Resolve() {
		out[k] = string(v)
	}
	return out
}

func TestReputationBucketsFollowTheScoreCeilings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		r    ReputationResolver
		want string
	}{
		{"a feed block wins over a good score", ReputationResolver{Score: 100, FeedBlocked: true}, ReputationBlocked},
		{"zero is hostile", ReputationResolver{Score: 0}, ReputationHostile},
		{"just under the hostile ceiling", ReputationResolver{Score: 19.9}, ReputationHostile},
		{"the hostile ceiling itself is suspect", ReputationResolver{Score: 20}, ReputationSuspect},
		{"just under the suspect ceiling", ReputationResolver{Score: 39.9}, ReputationSuspect},
		{"the suspect ceiling itself is good", ReputationResolver{Score: 40}, ReputationGood},
		{"a clean client", ReputationResolver{Score: 100}, ReputationGood},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.r.Name() != ResolverReputation {
				t.Fatalf("Name() = %q, want %q", tc.r.Name(), ResolverReputation)
			}
			got := resolvedValues(tc.r)
			if len(got) != 1 || got["bucket"] != tc.want {
				t.Fatalf("resolved %v, want bucket=%q", got, tc.want)
			}
		})
	}
}

func TestAdminAccessIsReportedOnlyOutsideTheAllowlist(t *testing.T) {
	t.Parallel()
	allowed := ParseAllowedAdminIPs([]string{"203.0.113.7", " 198.51.100.0/24 ", "2001:db8::1", "", "not-an-address"})
	if len(allowed) != 3 {
		t.Fatalf("parsed %d networks, want 3: an empty or unparseable entry must not become one", len(allowed))
	}
	cases := []struct {
		name, path, ip, want string
	}{
		{"a stranger on wp-admin", "/blog/wp-admin/options.php", "192.0.2.1", AdminAccessWPAdmin},
		{"a stranger on wp-login", "/wp-login.php", "192.0.2.1", AdminAccessWPLogin},
		{"a bare allowlisted address", "/wp-admin/", "203.0.113.7", ""},
		{"its neighbour is not allowlisted", "/wp-admin/", "203.0.113.8", AdminAccessWPAdmin},
		{"inside an allowlisted network", "/wp-admin/", "198.51.100.200", ""},
		{"an allowlisted IPv6 host", "/wp-login.php", "2001:db8::1", ""},
		{"its IPv6 neighbour is not", "/wp-login.php", "2001:db8::2", AdminAccessWPLogin},
		{"loopback is always allowed", "/wp-admin/", "127.0.0.1", ""},
		{"an address that does not parse is not on the list", "/wp-admin/", "garbage", AdminAccessWPAdmin},
		{"an ordinary path says nothing", "/products/42", "192.0.2.1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := AdminAccessResolver{Path: tc.path, ClientIP: tc.ip, Allowed: allowed}
			if r.Name() != ResolverAdminAccess {
				t.Fatalf("Name() = %q, want %q", r.Name(), ResolverAdminAccess)
			}
			got := resolvedValues(r)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("resolved %v, want nothing", got)
				}
				return
			}
			if got["surface"] != tc.want {
				t.Fatalf("resolved %v, want surface=%q", got, tc.want)
			}
		})
	}
}

func TestAnUnsetAdminAllowlistPermitsNobody(t *testing.T) {
	t.Parallel()
	r := AdminAccessResolver{Path: "/wp-admin/", ClientIP: "192.0.2.1"}
	if got := resolvedValues(r); got["surface"] != AdminAccessWPAdmin {
		t.Fatalf("resolved %v: a nil allowlist must not read as allow-everyone", got)
	}
}

func TestOriginMismatchIsReportedOnlyWhenTheArgumentDisagreesWithHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, target, host string
		want               bool
	}{
		{"no argument", "/amp?x=1", "shop.example", false},
		{"https origin matching the host", "/amp?__amp_source_origin=https%3A%2F%2Fshop.example", "shop.example", false},
		{"http origin matching the host", "/amp?__amp_source_origin=http%3A%2F%2Fshop.example", "shop.example", false},
		{"another site's origin", "/amp?__amp_source_origin=https%3A%2F%2Fevil.example", "shop.example", true},
		{"the host as a prefix of another", "/amp?__amp_source_origin=https%3A%2F%2Fshop.example.evil.example", "shop.example", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			req.Host = tc.host
			r := OriginResolver{Request: req}
			if r.Name() != ResolverOrigin {
				t.Fatalf("Name() = %q, want %q", r.Name(), ResolverOrigin)
			}
			got := resolvedValues(r)
			if tc.want && got["amp"] != OriginAMPMismatch {
				t.Fatalf("resolved %v, want amp=%q", got, OriginAMPMismatch)
			}
			if !tc.want && len(got) != 0 {
				t.Fatalf("resolved %v, want nothing", got)
			}
		})
	}
}

func TestOriginResolverSaysNothingWithoutARequestOrAHost(t *testing.T) {
	t.Parallel()
	if got := resolvedValues(OriginResolver{}); len(got) != 0 {
		t.Fatalf("no request resolved %v, want nothing", got)
	}
	req := httptest.NewRequest(http.MethodGet, "/amp?__amp_source_origin=https%3A%2F%2Fevil.example", nil)
	req.Host = ""
	if got := resolvedValues(OriginResolver{Request: req}); len(got) != 0 {
		t.Fatalf("no host resolved %v: there is nothing to disagree with", got)
	}
}

func TestPresentMatchesWhateverItIsHandedAndCannotBePrefiltered(t *testing.T) {
	t.Parallel()
	op := NewPresent("x-exploit")
	if op.Name() != "present:x-exploit" {
		t.Fatalf("Name() = %q", op.Name())
	}
	for _, v := range []string{"", "anything"} {
		if _, ok := op.Eval(nil, []byte(v)); !ok {
			t.Fatalf("Eval(%q) did not match; presence is the whole condition", v)
		}
	}
	if lits, ok := op.Literals(); ok || lits != nil {
		t.Fatalf("Literals() = %v, %v: presence has no required bytes, and claiming some would hide the rule from the prefilter", lits, ok)
	}
	if op.Cost() != types.CostLiteralMatch {
		t.Fatalf("Cost() = %v, want %v", op.Cost(), types.CostLiteralMatch)
	}
}

func TestSegmentCountMatchesAtItsThresholdAndNotBelow(t *testing.T) {
	t.Parallel()
	op := NewSegmentCount("depth", '/', 3)
	if op.Name() != "segments:depth" {
		t.Fatalf("Name() = %q", op.Name())
	}
	if _, ok := op.Eval(nil, []byte("/a/b")); ok {
		t.Fatal("two separators matched a threshold of three")
	}
	if _, ok := op.Eval(nil, []byte("/a/b/c")); !ok {
		t.Fatal("three separators did not match a threshold of three")
	}
	if lits, ok := op.Literals(); !ok || len(lits) != 1 || lits[0] != "/" {
		t.Fatalf("Literals() = %v, %v, want the separator", lits, ok)
	}
	if lits, ok := NewSegmentCount("any", '/', 0).Literals(); ok || lits != nil {
		t.Fatalf("a threshold of zero matches values without the separator, so it requires nothing; got %v, %v", lits, ok)
	}
	if op.Cost() != types.CostLiteralMatch {
		t.Fatalf("Cost() = %v, want %v", op.Cost(), types.CostLiteralMatch)
	}
}

func TestKeySuffixNarrowsItsInnerOperatorToMatchingKeys(t *testing.T) {
	t.Parallel()
	inner := NewSegmentCount("depth", '/', 1)
	op := ScopeToKeySuffix("password", inner)
	if op.Name() != "key~password:"+inner.Name() {
		t.Fatalf("Name() = %q", op.Name())
	}
	value := []byte("a/b")
	if _, ok := op.Eval(&rules.EvalContext{Key: "account.owner.password"}, value); !ok {
		t.Fatal("a key ending in the suffix did not reach the inner operator")
	}
	if _, ok := op.Eval(&rules.EvalContext{Key: "account.owner.name"}, value); ok {
		t.Fatal("a key without the suffix matched")
	}
	if _, ok := op.Eval(nil, value); ok {
		t.Fatal("a value with no key matched; no key is not a matching key")
	}
	if _, ok := op.Eval(&rules.EvalContext{Key: "user.password"}, []byte("ab")); ok {
		t.Fatal("the suffix matched but the inner operator did not, and the wrapper matched anyway")
	}
	wantLits, wantOK := inner.Literals()
	gotLits, gotOK := op.Literals()
	if gotOK != wantOK || len(gotLits) != len(wantLits) || gotLits[0] != wantLits[0] {
		t.Fatalf("Literals() = %v, %v, want the inner operator's %v, %v", gotLits, gotOK, wantLits, wantOK)
	}
	if op.Cost() != inner.Cost() {
		t.Fatalf("Cost() = %v, want the inner operator's %v", op.Cost(), inner.Cost())
	}
}

func TestDefaultRulesLoadsExactlyTheRulesAtOrBelowTheLevel(t *testing.T) {
	t.Parallel()
	catalog := RuleCatalog()
	if len(catalog) != len(defaultSpecs) {
		t.Fatalf("RuleCatalog has %d entries, the table has %d", len(catalog), len(defaultSpecs))
	}
	for _, level := range []int{1, 2, 3, 4} {
		want := map[types.RuleID]bool{}
		for _, info := range catalog {
			if info.ParanoiaLevel <= level {
				want[types.RuleID(info.ID)] = true
			}
		}
		got := DefaultRules(level)
		if len(got) != len(want) {
			t.Fatalf("level %d loads %d rules, the catalog says %d", level, len(got), len(want))
		}
		for _, r := range got {
			if !want[r.ID] {
				t.Fatalf("level %d loaded rule %d, which the catalog places above it", level, r.ID)
			}
		}
	}
	if len(DefaultRules(4)) <= len(DefaultRules(1)) {
		t.Fatal("level 4 loads no more than level 1, so the level filter is not being exercised")
	}
	if len(DefaultRules(0)) != len(DefaultRules(1)) || len(DefaultRules(-3)) != len(DefaultRules(1)) {
		t.Fatal("a level below 1 must load what level 1 loads, not nothing")
	}
}

func TestTheCatalogSaysWhereEachRuleComesFromAndWhatItDoes(t *testing.T) {
	t.Parallel()
	var fromGwaf, own, logging int
	for _, info := range RuleCatalog() {
		if info.From != 0 {
			fromGwaf++
		} else {
			own++
		}
		switch info.Action {
		case rules.Block.Name():
		case rules.Log.Name():
			logging++
		default:
			t.Fatalf("rule %d reports action %q, which is neither block nor log", info.ID, info.Action)
		}
		looked, ok := LookupRule(info.ID)
		if !ok || looked.Msg != info.Msg || looked.From != info.From {
			t.Fatalf("LookupRule(%d) = %+v, %v; the catalog says %+v", info.ID, looked, ok, info)
		}
	}
	if fromGwaf == 0 || own == 0 {
		t.Fatalf("%d rules from gwaf and %d of gateon's own: the catalog must show both kinds", fromGwaf, own)
	}
	if logging == 0 {
		t.Fatal("no rule reports the log action, yet the inbound leak rules only record")
	}
	if _, ok := LookupRule(1); ok {
		t.Fatal("LookupRule found an ID that is not in the table")
	}
}

func TestDLPResponseRulesAreTheResponsePhaseLeakRulesAndNothingElse(t *testing.T) {
	t.Parallel()
	set := DLPResponseRules(4)
	if len(set) == 0 {
		t.Fatal("no response-phase leak rules at the highest level")
	}
	for _, r := range set {
		if !IsDLPRule(r.ID) {
			t.Fatalf("rule %d is in the redaction set but IsDLPRule denies it", r.ID)
		}
		if r.Phase != types.PhaseResponseBody {
			t.Fatalf("rule %d is in the redaction set and runs in phase %v", r.ID, r.Phase)
		}
	}
	var responseLeaks int
	for _, info := range RuleCatalog() {
		isLeak := info.Category == CategoryDLP
		if IsDLPRule(types.RuleID(info.ID)) != isLeak {
			t.Fatalf("IsDLPRule(%d) = %v for a rule in category %q", info.ID, !isLeak, info.Category)
		}
		if isLeak && info.Phase == types.PhaseResponseBody {
			responseLeaks++
		}
	}
	if len(set) != responseLeaks {
		t.Fatalf("the redaction set has %d rules, the catalog has %d response-phase leak rules", len(set), responseLeaks)
	}
	if len(DLPResponseRules(0)) != len(DLPResponseRules(1)) {
		t.Fatal("a level below 1 must load what level 1 loads")
	}
}

func TestEveryDispositionHasAName(t *testing.T) {
	t.Parallel()
	seen := map[string]Disposition{}
	for _, d := range []Disposition{
		DispositionEngine, DispositionMiddleware, DispositionResolver,
		DispositionNative, DispositionMerged, DispositionDropped,
	} {
		name := d.String()
		if name == "" || name == "unknown" {
			t.Fatalf("disposition %d has no name", d)
		}
		if other, dup := seen[name]; dup {
			t.Fatalf("dispositions %d and %d share the name %q", other, d, name)
		}
		seen[name] = d
	}
}
