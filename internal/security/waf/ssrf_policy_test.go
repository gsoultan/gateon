// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf_test

import (
	"testing"

	secwaf "github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gwaf"
)

// fetchURL is a request handing the server a foreign URL to retrieve. It is SSRF
// on an application that does not do that by design, and a webhook registration
// on one that does — the request cannot tell them apart, which is exactly why
// the rule is a flag rather than a paranoia level.
// The hostname these requests arrive on. gwaf v0.4.1 compares a destination
// against origins the embedder declares, not the Host header the attacker
// writes, so every policy under test has to say what it answers on — an
// undeclared origin means the off-origin rules report nothing at all.
var testOrigins = []string{"app.example.com"}

const fetchURL = "/import?url=http%3A%2F%2Fevil.tld%2Fpayload"

func decide(t *testing.T, p secwaf.Policy, target string) gwaf.Decision {
	t.Helper()

	w, err := p.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine("GET", target, "HTTP/1.1")
	tx.AddRequestHeader("Host", "app.example.com")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
	return tx.ProcessRequestHeaders()
}

// postForm drives a form-encoded POST through both request phases and returns
// whichever decision refused it, or the body-phase decision if neither did.
//
// The body phase matters here: a form field is only an ARG once the body has
// been parsed, and the platform profiles are scoped to ARGS by name.
func postForm(t *testing.T, p secwaf.Policy, path, body string) gwaf.Decision {
	t.Helper()

	w, err := p.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine("POST", path, "HTTP/1.1")
	tx.AddRequestHeader("Host", "app.example.com")
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0")

	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return d
	}
	tx.SetRequestBody([]byte(body))
	return tx.ProcessRequestBody()
}

// TestSSRFParamRuleIsOffByDefault pins the default. An application that
// registers webhooks or imports avatars must not start blocking those because
// gateon was upgraded.
func TestSSRFParamRuleIsOffByDefault(t *testing.T) {
	t.Parallel()

	if d := decide(t, secwaf.Policy{Origins: testOrigins}, fetchURL); d.Blocked() {
		t.Errorf("server-side fetch blocked with SSRFProtection unset (rule %d: %s); "+
			"an upgrade would break every webhook registration", d.RuleID(), d.Message())
	}
}

// TestSSRFParamRuleBlocksWhenEnabled is the other half: the flag has to do
// something.
func TestSSRFParamRuleBlocksWhenEnabled(t *testing.T) {
	t.Parallel()

	d := decide(t, secwaf.Policy{SSRFProtection: true, Origins: testOrigins}, fetchURL)
	if !d.Blocked() {
		t.Fatalf("off-origin fetch URL not blocked with SSRFProtection set: verdict=%v score=%d",
			d.Verdict(), d.Score())
	}
	if d.RuleID() != secwaf.IDSSRFParam {
		t.Errorf("blocked by rule %d; want %d (IDSSRFParam)", d.RuleID(), secwaf.IDSSRFParam)
	}
}

// TestSSRFParamRuleIsNotReachableByParanoiaLevel is the distinction the constant
// exists to make. Raising paranoia says "I will pay for more depth"; it does not
// say "this application never fetches user-supplied URLs". Turning this on
// behind the operator's back at PL4 would break a webhook integration on a
// setting that reads as unrelated.
func TestSSRFParamRuleIsNotReachableByParanoiaLevel(t *testing.T) {
	t.Parallel()

	for pl := 1; pl <= 4; pl++ {
		d := decide(t, secwaf.Policy{ParanoiaLevel: pl, Origins: testOrigins}, fetchURL)
		if d.Blocked() && d.RuleID() == secwaf.IDSSRFParam {
			t.Errorf("PL%d enabled the SSRF fetch rule without the flag", pl)
		}
	}
}

// TestSSRFTagDisableStillWins checks the escape hatch. An operator who turned
// SSRF detection off has said so, and the opt-in must not route around it.
func TestSSRFTagDisableStillWins(t *testing.T) {
	t.Parallel()

	p := secwaf.Policy{
		SSRFProtection: true,
		DisabledTags:   map[string]bool{"ssrf": true},
		Origins:        testOrigins,
	}
	if d := decide(t, p, fetchURL); d.Blocked() && d.RuleID() == secwaf.IDSSRFParam {
		t.Error("SSRF rule fired despite the ssrf tag being disabled")
	}
}

// TestNavigationRedirectIsBlockedWithoutTheFlag pins the half of the same
// comparison that ships enabled in gwaf v0.4.0. An application sending its own
// users to another origin has no ordinary reading, so this needs no opt-in —
// and gateon must not have suppressed it.
func TestNavigationRedirectIsBlockedWithoutTheFlag(t *testing.T) {
	t.Parallel()

	d := decide(t, secwaf.Policy{Origins: testOrigins}, "/login?redirect_to=https%3A%2F%2Fevil.tld%2Fsteal")
	if !d.Blocked() {
		t.Errorf("open redirect not blocked by default: verdict=%v score=%d", d.Verdict(), d.Score())
	}
}

// TestSameOriginRedirectIsAllowed is the other half of the rule shipping
// enabled: an application navigating its own users around must not be blocked,
// or the first casualty is a login flow.
//
// Same-origin is decided against the declared origins now, not the request. If
// gateon ever stops supplying them, this still passes — which is why the test
// below exists as well.
func TestSameOriginRedirectIsAllowed(t *testing.T) {
	t.Parallel()

	d := decide(t, secwaf.Policy{Origins: testOrigins}, "/login?redirect_to=https%3A%2F%2Fapp.example.com%2Fdashboard")
	if d.Blocked() {
		t.Errorf("same-origin redirect blocked (rule %d: %s); the declared origins are not reaching the engine",
			d.RuleID(), d.Message())
	}
}

// TestOffOriginIgnoresASpoofedHostHeader is the bypass gwaf v0.4.1 fixed, pinned
// from gateon's side.
//
// v0.4.0 compared the destination against the request's Host header. The
// attacker writes that header as freely as the destination, so "Host: evil.tld"
// with "redirect_to=https://evil.tld/" compared same-origin and passed. The
// general form is worth keeping in mind: a verdict that depends on
// attacker-supplied data is not a verdict.
//
// gateon declares its origins from the routing table and operator config, so a
// request claiming to be evil.tld cannot make evil.tld an origin.
func TestOffOriginIgnoresASpoofedHostHeader(t *testing.T) {
	t.Parallel()

	p := secwaf.Policy{Origins: testOrigins}
	w, err := p.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine("GET", "/login?redirect_to=https%3A%2F%2Fevil.tld%2Fsteal", "HTTP/1.1")
	// The attacker names their own domain as the host, which is what made this
	// compare same-origin before.
	tx.AddRequestHeader("Host", "evil.tld")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0")

	if d := tx.ProcessRequestHeaders(); !d.Blocked() {
		t.Error("an off-origin redirect passed because the request claimed the attacker's domain as its host; " +
			"the comparison is reading the request instead of the configuration")
	}
}

// TestOffOriginRulesStayQuietWithoutOrigins documents the trade v0.4.1 made:
// with nothing trustworthy to compare against, the rules report nothing rather
// than guess. It is the safe answer and an easy one to not notice, which is why
// newWAFEngine logs when an install is in this state.
func TestOffOriginRulesStayQuietWithoutOrigins(t *testing.T) {
	t.Parallel()

	d := decide(t, secwaf.Policy{}, "/login?redirect_to=https%3A%2F%2Fevil.tld%2Fsteal")
	if d.Blocked() && d.RuleID() == 1013 {
		t.Error("the off-origin rule reached a verdict with no origins declared; it has nothing to compare against")
	}
}

// TestWordPressProfileSuppressesItsFalsePositive proves a profile changes what
// the engine does, using the case gwaf documents: WordPress's options API
// legitimately carries serialized PHP.
func TestWordPressProfileSuppressesItsFalsePositive(t *testing.T) {
	t.Parallel()

	// The profile is scoped to a path, a target and a field, so the comparison
	// has to be a request it actually covers — a comment POSTed as a form body,
	// which is how WordPress submits one. Sending the same payload in a query
	// string tests nothing: it lands on REQUEST_URI, an unkeyed target the
	// exception deliberately does not cover.
	const phpPayload = "comment=%3C%3Fphp+echo+%24name%3B+%3F%3E"

	// Without the profile this blocks, and correctly so — the bytes are PHP.
	// Asserting it first is what stops the suppression check below from passing
	// vacuously if the rule ever stops firing for an unrelated reason.
	if d := postForm(t, secwaf.Policy{Origins: testOrigins}, "/wp-comments-post.php", phpPayload); !d.Blocked() {
		t.Fatalf("PHP in a comment body is not blocked without the profile (verdict=%v)", d.Verdict())
	}

	d := postForm(t, secwaf.Policy{AppProfiles: []string{"wordpress"}, Origins: testOrigins}, "/wp-comments-post.php", phpPayload)
	if d.Blocked() {
		t.Errorf("wordpress profile did not suppress its own false positive: rule %d (%s)",
			d.RuleID(), d.Message())
	}
}

// TestAppProfileIsScopedNotAGlobalOff is the security half of the profile
// feature. An exception names a path and a field; the same payload arriving
// anywhere else is still an attack. If a profile turned the rule off outright,
// selecting a platform in the dashboard would be a way to disable detection.
func TestAppProfileIsScopedNotAGlobalOff(t *testing.T) {
	t.Parallel()

	p := secwaf.Policy{AppProfiles: []string{"wordpress"}, Origins: testOrigins}
	const phpPayload = "comment=%3C%3Fphp+echo+%24name%3B+%3F%3E"

	// Same payload, same field name, a path the profile does not cover.
	if d := postForm(t, p, "/upload.php", phpPayload); !d.Blocked() {
		t.Error("the wordpress profile suppressed PHP injection outside the path it excepts")
	}

	// The excepted path, a field the profile does not cover.
	if d := postForm(t, p, "/wp-comments-post.php",
		"author=%3C%3Fphp+echo+%24name%3B+%3F%3E"); !d.Blocked() {
		t.Error("the wordpress profile suppressed PHP injection outside the field it excepts")
	}
}
