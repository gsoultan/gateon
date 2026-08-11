// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/core"
	"github.com/gsoultan/gwaf/types"
)

// IDCRLFHeaderInjection is gwaf's opt-in CRLF rule, admitted from paranoia
// level 2 upwards. See crlfRuleMinParanoia.
const IDCRLFHeaderInjection types.RuleID = 1007

// crlfRuleMinParanoia is the paranoia level at which CRLF header injection
// detection is switched on.
//
// gwaf leaves this rule out of its default set for a measured reason: it is the
// only rule needing a transform chain that preserves line breaks, and that
// chain is materialised over every value of every request — 15.4µs versus
// 14.2µs on benign POST JSON, against a 15µs budget. One rule cannot spend 8%
// of the budget on requests it cannot match.
//
// Paranoia level is exactly the dial for that trade: PL1 is the latency-first
// default, and an operator who raises it has already said they will pay for
// depth. Response splitting is a real path to cache poisoning and session
// fixation, so it should be reachable — just not for free.
const crlfRuleMinParanoia = 2

// IDWordPressHardening and IDLoopbackSSRF are gwaf's other two opt-in rules.
// They are left out of gwaf's default set for the same reason CRLF is — not
// because they are imprecise, but because each is wrong for a specific class of
// deployment — so gateon admits them where it can tell the class is not present.
const (
	IDWordPressHardening types.RuleID = 1011
	IDLoopbackSSRF       types.RuleID = 11003
)

// IDSSRFParam is gwaf's server-side-fetch rule: an absolute off-origin URL in a
// parameter the application will itself retrieve — "url", "callback", "webhook",
// "feed". The ID is the one gwaf documents for it.
//
// It is opt-in rather than paranoia-gated, and that distinction is the whole
// point. Paranoia level asks "how much depth will you pay for?", and this rule
// does not answer that question — it is cheap and precise. It asks a different
// one: does this application fetch user-supplied URLs by design? Registering a
// webhook, importing an avatar and subscribing to a feed are all "hand the
// server a foreign URL and let it fetch that", which is byte-for-byte what SSRF
// is. Only the deployment knows which it is, so raising paranoia must not switch
// this on behind the operator's back.
//
// The navigation half of the same comparison — "redirect_to", "next", "goto" —
// needs no flag and ships in gwaf's default set, because an application sending
// its own users to another origin has no ordinary reading.
const IDSSRFParam types.RuleID = 1016

// wpHardeningMinParanoia is the paranoia level at which direct PHP execution
// anywhere under wp-content is blocked, not just inside the upload directories.
//
// gwaf's core rule 1010 already covers uploads, where execution is never
// intended by anyone. This goes further and covers the whole content tree, which
// is the hardening every WordPress guide recommends and which a minority of
// plugins genuinely break under — they expose an endpoint by having the browser
// request their PHP file directly instead of routing through index.php.
//
// That is a tuning decision, so it belongs on the tuning dial rather than in the
// default. PL2 is the same threshold CRLF uses and means the same thing: the
// operator has said they will pay for depth.
const wpHardeningMinParanoia = 2

// loopbackSSRFMinParanoia is the paranoia level at which a loopback or
// link-local target in a request value is blocked.
//
// "localhost" and "127.0.0.1" are ordinary values in CI configuration, staging
// traffic, and webhooks pointed at a development tunnel, so gwaf keeps this out
// of its default set — it is the rule that gets a WAF switched off in week one.
// A gateway fronting production is the deployment where that reading is least
// likely, but "least likely" is not "never", which is why it is PL3 rather than
// PL2: the operator has to ask for it twice.
const loopbackSSRFMinParanoia = 3

// Policy is gateon's description of how a WAF instance should behave. It is the
// typed replacement for the SecLang preamble that createWAFInstance used to
// build by string concatenation — roughly twenty directives whose only reader
// was the engine.
//
// Building it as data rather than text matters beyond tidiness: a mistyped
// directive used to be a rule that silently never fired, and there was no
// point at which anything could check it. A Policy either compiles or does not.
type Policy struct {
	// ParanoiaLevel selects how much of the corpus loads, 1 to 4. It governs
	// both which gateon rules are included and gwaf's minimum confidence, which
	// must agree or a rule would be loaded and then discarded.
	ParanoiaLevel int

	// AnomalyThreshold is the accumulated score at which a request is refused.
	AnomalyThreshold int

	// DetectionOnly evaluates rules and reports without enforcing. It is the
	// rollout posture, not the destination.
	DetectionOnly bool

	// FailOpen permits requests the engine could not fully analyse. The default
	// is to fail closed: gwaf refuses what it could not inspect, which is the
	// right default for a security control and the wrong one for availability.
	// Whichever gateon picks, it is stated rather than inherited.
	FailOpen bool

	// BlockStatus is the HTTP status for a block that names no status itself.
	BlockStatus int

	// Limits bound the input the engine will inspect.
	Limits gwaf.Limits

	// ResponseInspection enables the response-phase rules. Response inspection
	// is the most expensive part of the WAF, so it is off outside the
	// enterprise tier.
	ResponseInspection bool

	// CoreRulesetDisabled omits gwaf's first-party rules, leaving only
	// gateon's. It exists so tests can assert that a specific gateon rule
	// fires: gwaf's core blocks first and blocking is terminal, so with the
	// core loaded a gateon rule covering the same attack is never reached and
	// its absence would look like a pass. Production never sets it — a WAF
	// without the core ruleset is a materially weaker one.
	CoreRulesetDisabled bool

	// DisabledCategories names rule categories the operator has turned off,
	// matched against spec.category. It carries the disable_sqli, disable_xss,
	// disable_php and friends from WafConfig.
	DisabledCategories map[string]bool

	// DisabledTags names rule tags to exclude, which is the finer-grained form
	// of the same control.
	DisabledTags map[string]bool

	// ExtraRules are operator-authored rules from the database.
	ExtraRules rules.Set

	// Exceptions suppress specific rules, replacing SecRuleRemoveById.
	Exceptions []rules.Exception

	// AppProfiles names the platforms this route serves, each selecting a set of
	// scoped exceptions for the false positives that platform generates against
	// itself. See AppProfile.
	AppProfiles []string

	// SSRFProtection admits IDSSRFParam, which blocks an off-origin URL in a
	// parameter the server itself fetches. It is a statement about the
	// application — that it does not take user-supplied URLs to retrieve — and
	// not a depth setting, which is why it is a flag and not a paranoia level.
	SSRFProtection bool

	// Origins are the hostnames this gateway answers on, and they are what the
	// off-origin redirect and SSRF rules compare a destination against.
	//
	// They must come from configuration. gwaf v0.4.0 compared against the Host
	// header and v0.4.1 fixed it as a security bug: an attacker supplies Host as
	// freely as the destination, so "Host: evil.tld" with
	// "redirect_to=https://evil.tld/" compared same-origin and passed. A verdict
	// that depends on attacker-supplied data is not a verdict.
	//
	// Left empty, those rules report nothing rather than guess. That is gwaf's
	// choice and the right one, but it means an install that declares no origins
	// silently loses open-redirect coverage — so gateon fills this from the
	// routing table, which is configuration, and says so when it cannot.
	Origins []string

	// Logger receives engine diagnostics.
	Logger Logger

	// OnDecision receives every decision, and is how threat records, metrics
	// and the audit log are produced. It runs on the request path, so it must
	// not block.
	OnDecision func(gwaf.Decision)
}

// Logger is the subset of *slog.Logger gwaf requires, restated so this package
// does not force a logging choice on its callers.
type Logger interface{ Enabled() bool }

// Reputation thresholds, restated from the SecLang rules they replace. The
// original expressed these as four rules that raised tx.inbound_anomaly_score_
// threshold as reputation improved: a well-behaved client is given more room
// before its accumulated score refuses it.
//
// This is a policy statement, so it belongs in one readable function rather
// than in four rules whose interaction had to be inferred from load order.
func thresholdFor(base int, reputation float64) int {
	switch {
	case reputation >= 95:
		return maxInt(base, 15)
	case reputation >= 80:
		return maxInt(base, 12)
	case reputation >= 40:
		return maxInt(base, 10)
	case reputation >= 15:
		return maxInt(base, 7)
	default:
		return base
	}
}

// ThresholdFor exposes the reputation-scaled anomaly threshold.
func (p Policy) ThresholdFor(reputation float64) int {
	return thresholdFor(p.anomalyThreshold(), reputation)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (p Policy) paranoiaLevel() int {
	if p.ParanoiaLevel < 1 {
		return 1
	}
	if p.ParanoiaLevel > 4 {
		return 4
	}
	return p.ParanoiaLevel
}

func (p Policy) anomalyThreshold() int {
	if p.AnomalyThreshold <= 0 {
		return 5 // the CRS inbound default, carried over so thresholds mean the same thing
	}
	return p.AnomalyThreshold
}

func (p Policy) blockStatus() int {
	if p.BlockStatus == 0 {
		return 403
	}
	return p.BlockStatus
}

// Ruleset assembles the rules this policy admits: gateon's first-party corpus
// filtered by paranoia level and by the operator's category and tag
// exclusions, plus any operator-authored rules.
func (p Policy) Ruleset() rules.Set {
	pl := p.paranoiaLevel()
	set := make(rules.Set, 0, len(defaultSpecs)+len(p.ExtraRules))

	for _, s := range defaultSpecs {
		if s.pl > pl {
			continue
		}
		if !p.ResponseInspection && s.phase == types.PhaseResponseBody {
			continue
		}
		if p.DisabledCategories[s.category] || p.tagDisabled(s.tags) {
			continue
		}
		set = append(set, s.rule())
	}

	set = append(set, p.optInRules(pl)...)
	return append(set, p.ExtraRules...)
}

// optInRules are gwaf's core rules that its default set deliberately omits, and
// which gateon admits once it can tell the deployment is not the one each is
// wrong for.
//
// They are separated from Ruleset because they are selected on a different
// basis: everything in defaultSpecs is filtered by one uniform rule, while each
// of these carries its own argument for when it becomes correct.
func (p Policy) optInRules(pl int) rules.Set {
	var set rules.Set

	if pl >= crlfRuleMinParanoia && !p.tagDisabled([]string{"crlf", "response-splitting"}) {
		set = append(set, core.CRLFHeaderRule(IDCRLFHeaderInjection))
	}

	// The WordPress switch is honoured here as well as through the category
	// filter: an operator who turned WordPress detection off is not asking for
	// its strictest rule to arrive by another door.
	if pl >= wpHardeningMinParanoia && !p.DisabledCategories["WordPress"] &&
		!p.tagDisabled([]string{"wordpress", "wp_scan"}) {
		set = append(set, core.WordPressHardeningRule(IDWordPressHardening))
	}

	if pl >= loopbackSSRFMinParanoia && !p.tagDisabled([]string{"ssrf"}) {
		set = append(set, core.LoopbackSSRFRule(IDLoopbackSSRF))
	}

	// Unlike the three above, this one is not reachable by raising paranoia:
	// whether the application fetches user-supplied URLs is a property of the
	// application, not of how strict the operator wants to be. The tag switch
	// still applies, so turning SSRF detection off turns this off too.
	if p.SSRFProtection && !p.tagDisabled([]string{"ssrf"}) {
		set = append(set, core.SSRFParamRule(IDSSRFParam))
	}

	return set
}

func (p Policy) tagDisabled(tags []string) bool {
	for _, t := range tags {
		if p.DisabledTags[t] {
			return true
		}
	}
	return false
}

// Options renders the policy as gwaf options.
func (p Policy) Options() []gwaf.Option {
	mode := gwaf.Blocking
	if p.DetectionOnly {
		mode = gwaf.DetectionOnly
	}
	failMode := gwaf.FailClosed
	if p.FailOpen {
		failMode = gwaf.FailOpen
	}

	limits := p.Limits
	if limits.MaxBodySize == 0 {
		limits = gwaf.DefaultLimits()
	}

	opts := []gwaf.Option{
		gwaf.WithMode(mode),
		gwaf.WithFailMode(failMode),
		gwaf.WithLimits(limits),
		gwaf.WithThreshold(p.anomalyThreshold()),
		gwaf.WithBlockStatus(p.blockStatus()),
		// Confidence and paranoia level are two statements about the same
		// thing. Setting both from one source keeps them from drifting.
		gwaf.WithMinConfidence(types.ConfidenceFromParanoiaLevel(p.paranoiaLevel())),
		gwaf.WithRuleset(p.Ruleset()),
	}

	if len(p.Origins) > 0 {
		opts = append(opts, gwaf.WithOrigins(p.Origins...))
	}

	if p.CoreRulesetDisabled {
		opts = append(opts, gwaf.WithoutCoreRuleset())
	}

	// Order is deliberate: gateon's own carve-outs, then the platform profiles,
	// then whatever the operator wrote. Exceptions are matched rather than
	// applied in sequence, so this does not change behaviour — it is the order a
	// reader needs to see them in to understand where one came from.
	exceptions := DefaultExceptions()
	profileExceptions, _ := AppProfileExceptions(p.AppProfiles)
	exceptions = append(exceptions, profileExceptions...)
	exceptions = append(exceptions, p.Exceptions...)
	opts = append(opts, gwaf.WithExceptions(exceptions...))
	if p.OnDecision != nil {
		opts = append(opts, gwaf.OnDecision(p.OnDecision))
	}
	return opts
}

// UnknownAppProfiles names the configured profiles this build cannot resolve.
//
// It is separate from Options so that building an engine never fails on a
// misspelled profile — the ruleset is still correct without it — while the
// caller is still able to say so. Silence here would let an operator believe
// they had tuning they do not have.
func (p Policy) UnknownAppProfiles() []string {
	_, unknown := AppProfileExceptions(p.AppProfiles)
	return unknown
}

// NewEngine builds the WAF this policy describes.
func (p Policy) NewEngine() (*gwaf.WAF, error) {
	return gwaf.New(p.Options()...)
}
