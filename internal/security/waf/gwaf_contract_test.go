// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package waf_test

import (
	"iter"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/types"
)

// This file pins the gwaf API surface gateon depends on. gwaf is pinned to a
// v0.x tag, which carries no compatibility promise, so every symbol gateon
// builds on is exercised here: an upstream change breaks this test at build
// time instead of silently changing what the gateway blocks.
//
// It is deliberately a black-box (_test package) build so it sees only the
// exported surface, the same way the middleware does.

// TestEngineBlocksStructuralSQLi is the smoke test for the whole migration: a
// default WAF, no gateon rules, must block a textbook injection.
func TestEngineBlocksStructuralSQLi(t *testing.T) {
	t.Parallel()

	w, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine("GET", "/products?id=1%27+OR+%271%27%3D%271", "HTTP/1.1")
	tx.AddRequestHeader("Host", "shop.example.com")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0")

	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		t.Fatalf("SQLi not blocked: verdict=%v reason=%v score=%d rules=%d",
			d.Verdict(), d.Reason(), d.Score(), d.RulesEvaluated())
	}
	if d.RuleID() == 0 {
		t.Error("block carried no rule ID; audit output would be unattributable")
	}
	if d.Status() == 0 {
		t.Error("block carried no HTTP status")
	}
}

// TestEngineAllowsBenignRequest guards the other half: the corpus gateon serves
// must not trip the default ruleset.
func TestEngineAllowsBenignRequest(t *testing.T) {
	t.Parallel()

	w, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine("GET", "/products?id=42&sort=price_desc", "HTTP/1.1")
	tx.AddRequestHeader("Host", "shop.example.com")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	tx.AddRequestHeader("Accept", "text/html,application/xhtml+xml")

	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		t.Fatalf("benign request blocked by rule %d (%s)", d.RuleID(), d.Message())
	}
}

// TestDetectionOnlyModeDoesNotBlock pins the rollout posture: gateon ships the
// new engine in detection-only first, and that must observe without enforcing.
func TestDetectionOnlyModeDoesNotBlock(t *testing.T) {
	t.Parallel()

	w, err := gwaf.New(gwaf.WithMode(gwaf.DetectionOnly))
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	if w.Mode() != gwaf.DetectionOnly {
		t.Fatalf("mode = %v, want DetectionOnly", w.Mode())
	}

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine("GET", "/products?id=1%27+OR+%271%27%3D%271", "HTTP/1.1")
	tx.AddRequestHeader("Host", "shop.example.com")

	d := tx.ProcessRequestHeaders()
	if d.Blocked() {
		t.Fatal("detection-only mode blocked a request")
	}
	// The match must still be observable, or detection-only reports nothing.
	if len(tx.Matches()) == 0 && d.Score() == 0 {
		t.Error("detection-only produced neither matches nor score")
	}
}

// TestUserRuleIDRangeCoversGateonRules asserts the range gateon's existing rule
// IDs live in. gateon seeds rules numbered 1100010..1910002; gwaf reserves
// everything below types.UserMin for itself. If upstream ever raises UserMin
// above those IDs, every gateon rule silently fails to compile — so the
// boundary is asserted rather than assumed.
func TestUserRuleIDRangeCoversGateonRules(t *testing.T) {
	t.Parallel()

	const (
		lowestGateonRuleID  = types.RuleID(1_100_010)
		highestGateonRuleID = types.RuleID(1_910_002)
	)

	if types.UserMin > lowestGateonRuleID {
		t.Fatalf("types.UserMin = %d, above gateon's lowest rule ID %d",
			types.UserMin, lowestGateonRuleID)
	}
	if types.UserMax < highestGateonRuleID {
		t.Fatalf("types.UserMax = %d, below gateon's highest rule ID %d",
			types.UserMax, highestGateonRuleID)
	}
	if !lowestGateonRuleID.IsUser() || !highestGateonRuleID.IsUser() {
		t.Error("gateon rule IDs are not in the user namespace")
	}
}

// TestCustomRuleCompilesAndBlocks exercises the authoring surface gateon's
// converted ruleset is built from: Rule literals, targets, transforms, the
// ContainsAny operator (the @pm replacement) and BlockWithStatus.
func TestCustomRuleCompilesAndBlocks(t *testing.T) {
	t.Parallel()

	const ruleID = types.RuleID(1_210_001)

	set := rules.Set{{
		ID:         ruleID,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Transforms: []rules.Transform{transform.Lowercase},
		Op:         op.ContainsAny("sportsbook", "baccarat"),
		Actions:    []rules.Action{rules.BlockWithStatus(403)},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "Online Gambling Site Detected",
		Tags:       []string{"gambling"},
	}}

	w, err := gwaf.New(gwaf.WithRuleset(set))
	if err != nil {
		t.Fatalf("gwaf.New with custom ruleset: %v", err)
	}

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine("GET", "/?q=BACCARAT", "HTTP/1.1")

	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		t.Fatal("custom rule did not block")
	}
	if d.RuleID() != ruleID {
		t.Errorf("blocked by rule %d, want %d", d.RuleID(), ruleID)
	}
	if d.Status() != 403 {
		t.Errorf("status = %d, want 403", d.Status())
	}
}

// TestParanoiaLevelMapsToConfidence pins the mapping gateon uses to translate
// its stored paranoia level onto gwaf's confidence floor.
func TestParanoiaLevelMapsToConfidence(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		pl   int
		want types.Confidence
	}{
		{0, types.High}, // clamps up
		{1, types.High},
		{2, types.Medium},
		{3, types.Low},
		{4, types.Heuristic},
		{9, types.Heuristic}, // clamps down
	} {
		if got := types.ConfidenceFromParanoiaLevel(tc.pl); got != tc.want {
			t.Errorf("ConfidenceFromParanoiaLevel(%d) = %v, want %v", tc.pl, got, tc.want)
		}
	}
}

// TestResolverSuppliesReputation pins the mechanism that replaces gateon's
// X-Gateon-Reputation header round-trip. The score reaches a rule without ever
// being written into a request header an attacker could also write.
func TestResolverSuppliesReputation(t *testing.T) {
	t.Parallel()

	const ruleID = types.RuleID(1_910_002)

	set := rules.Set{{
		ID:      ruleID,
		Phase:   types.PhaseRequestHeaders,
		Targets: []types.Target{{Kind: types.TargetResolved, Name: "reputation"}},
		// Deliberately an exact match on the bucket name rather than a numeric
		// comparison: gwaf ships no numeric operator, which is why gateon
		// resolves reputation to a bucket rather than a score.
		Op:         op.Equals("hostile"),
		Actions:    []rules.Action{rules.BlockWithStatus(403)},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "Internal behaviour reputation block",
		Tags:       []string{"reputation"},
	}}

	w, err := gwaf.New(gwaf.WithRuleset(set))
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	tx := w.NewTransaction()
	defer tx.Close()

	tx.AddResolver(staticResolver{name: "reputation", key: "bucket", value: "hostile"})
	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine("GET", "/", "HTTP/1.1")

	d := tx.ProcessRequestHeaders()
	if !d.Blocked() {
		t.Fatal("resolver-driven rule did not block")
	}
	if d.RuleID() != ruleID {
		t.Errorf("blocked by rule %d, want %d", d.RuleID(), ruleID)
	}
}

// TestMatchesCarryForensics pins the fields gateon's threat records and the
// security dashboard are rebuilt on now that CRS rule IDs are gone.
func TestMatchesCarryForensics(t *testing.T) {
	t.Parallel()

	w, err := gwaf.New(gwaf.WithMode(gwaf.DetectionOnly))
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine("GET", "/products?id=1%27+OR+%271%27%3D%271", "HTTP/1.1")

	tx.ProcessRequestHeaders()

	ms := tx.Matches()
	if len(ms) == 0 {
		t.Fatal("no matches recorded for an injection payload")
	}
	m := ms[0]
	if m.RuleID == 0 || m.Msg == "" {
		t.Errorf("match lacks identity: id=%d msg=%q", m.RuleID, m.Msg)
	}
	if !m.Severity.Valid() || !m.Confidence.Valid() {
		t.Errorf("match lacks severity/confidence: %v/%v", m.Severity, m.Confidence)
	}
	if m.Interpretation == "" {
		t.Error("match lacks an interpretation; evasion reporting depends on it")
	}
}

// TestOnDecisionFires pins the telemetry hook that replaces Coraza's
// ProcessLogging.
func TestOnDecisionFires(t *testing.T) {
	t.Parallel()

	var got gwaf.Decision
	var calls int

	w, err := gwaf.New(
		gwaf.WithMode(gwaf.DetectionOnly),
		gwaf.OnDecision(func(d gwaf.Decision) {
			calls++
			got = d
		}),
	)
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	tx := w.NewTransaction()
	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine("GET", "/products?id=1%27+OR+%271%27%3D%271", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.Close()

	if calls == 0 {
		t.Fatal("OnDecision never fired; gateon would record no threats")
	}
	if got.RuleID() == 0 {
		t.Error("OnDecision decision carried no rule ID")
	}
}

// TestExceptionSuppressesRule pins the replacement for SecRuleRemoveById, which
// is how operators clear a false positive.
func TestExceptionSuppressesRule(t *testing.T) {
	t.Parallel()

	const ruleID = types.RuleID(1_210_002)

	set := rules.Set{{
		ID:         ruleID,
		Phase:      types.PhaseRequestHeaders,
		Targets:    []types.Target{{Kind: types.TargetArgs}},
		Op:         op.Contains("needle"),
		Actions:    []rules.Action{rules.Block},
		Severity:   types.SeverityCritical,
		Confidence: types.Certain,
		Msg:        "test rule",
	}}

	w, err := gwaf.New(
		gwaf.WithRuleset(set),
		gwaf.WithException(rules.Exception{
			RuleID: ruleID,
			Path:   "/legacy/*",
			Note:   "contract test",
		}),
	)
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	// Suppressed on the excepted path.
	tx := w.NewTransaction()
	tx.SetRequestLine("GET", "/legacy/import?q=needle", "HTTP/1.1")
	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		t.Error("exception did not suppress the rule on its path")
	}
	tx.Close()

	// Still enforced everywhere else.
	tx2 := w.NewTransaction()
	tx2.SetRequestLine("GET", "/api/import?q=needle", "HTTP/1.1")
	if d := tx2.ProcessRequestHeaders(); !d.Blocked() {
		t.Error("exception leaked outside its path")
	}
	tx2.Close()
}

// TestResponsePhaseStreams pins the streaming response API that lets gateon
// stop buffering whole responses in memory.
func TestResponsePhaseStreams(t *testing.T) {
	t.Parallel()

	w, err := gwaf.New(gwaf.WithMode(gwaf.DetectionOnly))
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}

	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRequestLine("GET", "/", "HTTP/1.1")
	tx.ProcessRequestHeaders()

	tx.SetResponseStatus(200)
	tx.AddResponseHeader("Content-Type", "text/plain")
	if d := tx.ProcessResponseHeaders(); d.Blocked() {
		t.Fatalf("benign response headers blocked: %s", d.Message())
	}

	// A private key in the response body is one of the DLP rules gwaf ships.
	body := "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----"
	tx.WriteResponseBody([]byte(body))
	tx.ProcessResponseBody()

	if tx.Score() == 0 && len(tx.Matches()) == 0 {
		t.Error("response-body leak produced no match; DLP coverage is not wired")
	}
}

// TestLimitsAreExplicit pins the knobs gateon maps its tier defaults onto.
func TestLimitsAreExplicit(t *testing.T) {
	t.Parallel()

	l := gwaf.DefaultLimits()
	if l.MaxBodySize <= 0 || l.MaxArgs <= 0 || l.MaxHeaders <= 0 ||
		l.MaxValueLen <= 0 || l.MaxArenaSize <= 0 {
		t.Fatalf("DefaultLimits has a zero bound: %+v", l)
	}

	if _, err := gwaf.New(
		gwaf.WithLimits(gwaf.Limits{
			MaxBodySize:  1 << 20,
			MaxArgs:      512,
			MaxHeaders:   128,
			MaxValueLen:  2 << 20,
			MaxArenaSize: 4 << 20,
		}),
		gwaf.WithFailMode(gwaf.FailClosed),
		gwaf.WithThreshold(5),
		gwaf.WithBlockStatus(403),
		gwaf.WithMinConfidence(types.High),
		gwaf.WithParanoiaLevel(1),
	); err != nil {
		t.Fatalf("gwaf.New with gateon's full option set: %v", err)
	}
}

// staticResolver is the minimum rules.Resolver implementation, used to pin the
// interface shape gateon's reputation resolver has to satisfy.
type staticResolver struct {
	name  string
	key   string
	value string
}

func (r staticResolver) Name() string { return r.name }

func (r staticResolver) Resolve() iter.Seq2[string, []byte] {
	return func(yield func(string, []byte) bool) {
		yield(r.key, []byte(r.value))
	}
}
