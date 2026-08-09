// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

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

	if d := decide(t, secwaf.Policy{}, fetchURL); d.Blocked() {
		t.Errorf("server-side fetch blocked with SSRFProtection unset (rule %d: %s); "+
			"an upgrade would break every webhook registration", d.RuleID(), d.Message())
	}
}

// TestSSRFParamRuleBlocksWhenEnabled is the other half: the flag has to do
// something.
func TestSSRFParamRuleBlocksWhenEnabled(t *testing.T) {
	t.Parallel()

	d := decide(t, secwaf.Policy{SSRFProtection: true}, fetchURL)
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
		d := decide(t, secwaf.Policy{ParanoiaLevel: pl}, fetchURL)
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

	d := decide(t, secwaf.Policy{}, "/login?redirect_to=https%3A%2F%2Fevil.tld%2Fsteal")
	if !d.Blocked() {
		t.Errorf("open redirect not blocked by default: verdict=%v score=%d", d.Verdict(), d.Score())
	}
}

// TestSameOriginRedirectIsAllowed is the regression this whole v0.4.0 feature
// turns on, and the one most likely to break silently. The rule is same-origin
// aware only because rules.EvalContext carries the request Host, which gwaf
// derives from the Host *header* — and Go's net/http strips Host from
// r.Header and promotes it to r.Host. If gateon ever stops re-injecting it
// (internal/middleware/waf.go), this rule loses its comparison and starts
// blocking an application navigating itself, which is an outage on a login flow.
func TestSameOriginRedirectIsAllowed(t *testing.T) {
	t.Parallel()

	d := decide(t, secwaf.Policy{}, "/login?redirect_to=https%3A%2F%2Fapp.example.com%2Fdashboard")
	if d.Blocked() {
		t.Errorf("same-origin redirect blocked (rule %d: %s); the request Host is not reaching the engine",
			d.RuleID(), d.Message())
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
	if d := postForm(t, secwaf.Policy{}, "/wp-comments-post.php", phpPayload); !d.Blocked() {
		t.Fatalf("PHP in a comment body is not blocked without the profile (verdict=%v)", d.Verdict())
	}

	d := postForm(t, secwaf.Policy{AppProfiles: []string{"wordpress"}}, "/wp-comments-post.php", phpPayload)
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

	p := secwaf.Policy{AppProfiles: []string{"wordpress"}}
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
