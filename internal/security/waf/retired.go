// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

// Disposition describes what became of a SecLang rule that gateon used to seed
// into the waf_rules table and no longer ships as a detection rule.
type Disposition uint8

const (
	// DispositionEngine means the directive configured the engine rather than
	// detecting anything. It is now a typed option in policy.go.
	DispositionEngine Disposition = iota

	// DispositionMiddleware means the check survives, but outside the WAF,
	// because it needs state or protocol context a stateless rule engine does
	// not have.
	DispositionMiddleware

	// DispositionResolver means the signal it carried now crosses into the
	// engine as a resolver value instead of a request header.
	DispositionResolver

	// DispositionNative means gwaf performs the check in the engine, so a rule
	// expressing it would be redundant.
	DispositionNative

	// DispositionMerged means the detection is still present under a different
	// rule ID.
	DispositionMerged

	// DispositionDropped means the check is gone and nothing replaces it. Every
	// entry with this disposition is a coverage reduction and says so.
	DispositionDropped
)

// String implements fmt.Stringer.
func (d Disposition) String() string {
	switch d {
	case DispositionEngine:
		return "engine-option"
	case DispositionMiddleware:
		return "middleware"
	case DispositionResolver:
		return "resolver"
	case DispositionNative:
		return "native"
	case DispositionMerged:
		return "merged"
	default:
		return "dropped"
	}
}

// Retirement records the fate of one retired rule.
type Retirement struct {
	// ID is the SecLang rule ID as it appeared in waf_rules.
	ID string

	// Name is the rule's old display name, so an operator recognises it.
	Name string

	// Disposition is what happened to it.
	Disposition Disposition

	// Replacement names where the behaviour lives now, or is empty when
	// Disposition is DispositionDropped.
	Replacement string

	// Why explains the decision in one sentence. It is shown in the dashboard
	// next to the retired rule, because "your rule is gone" without a reason is
	// indistinguishable from a bug.
	Why string
}

// Repeated rationales, named once. Several rules were retired for the same
// reason, and restating it per row invites the copies to drift apart.
const (
	whyReputationThreshold = "reputation-scaled thresholds are computed by gateon and passed to the engine per instance."
	whyPerRequestBodyLimit = "gwaf's body limit is fixed per engine instance, so a per-request limit has to be enforced before the engine sees the body."

	replacementThresholdFor = "Policy.thresholdFor"
	replacementMaxBody      = "maxbody middleware"
	replacementNoneNeeded   = "none needed"
)

// Retirements accounts for every seeded SecLang directive that did not become a
// typed rule in ruleset.go.
//
// It is exhaustive by construction: TestEverySeededRuleIsAccountedFor walks the
// original seed corpus and fails if an ID appears in neither defaultSpecs nor
// this table. That test is the reason a rule cannot be lost by accident during
// the migration — the compiler cannot check it, so a test does.
var Retirements = []Retirement{
	{
		ID: "1900300", Name: "Redact Sensitive Headers",
		Disposition: DispositionEngine, Replacement: "audit log redaction",
		Why: "setvar:tx.redact_headers configured Coraza's audit writer; gateon writes its own audit records now and redacts at the writer.",
	},
	{
		ID: "1900015", Name: "Set Server Name from Host",
		Disposition: DispositionEngine, Replacement: replacementNoneNeeded,
		Why: "seeded a SecLang variable for other rules to read; nothing in the typed corpus reads it.",
	},
	{
		ID: "1900001", Name: "Default Anomaly Threshold",
		Disposition: DispositionEngine, Replacement: "gwaf.WithThreshold",
		Why: "the inbound anomaly threshold is an engine option, not a rule.",
	},
	{
		ID: "1900010", Name: "Adaptive Threshold: Reputation 95+",
		Disposition: DispositionEngine, Replacement: replacementThresholdFor,
		Why: whyReputationThreshold,
	},
	{
		ID: "1900011", Name: "Adaptive Threshold: Reputation 80+",
		Disposition: DispositionEngine, Replacement: replacementThresholdFor,
		Why: whyReputationThreshold,
	},
	{
		ID: "1900012", Name: "Adaptive Threshold: Reputation 15+",
		Disposition: DispositionEngine, Replacement: replacementThresholdFor,
		Why: whyReputationThreshold,
	},
	{
		ID: "1900013", Name: "Adaptive Threshold: Reputation 40+",
		Disposition: DispositionEngine, Replacement: replacementThresholdFor,
		Why: whyReputationThreshold,
	},
	{
		ID: "1900400", Name: "Adaptive Body Limit: High Reputation",
		Disposition: DispositionMiddleware, Replacement: replacementMaxBody,
		Why: whyPerRequestBodyLimit,
	},
	{
		ID: "1900401", Name: "Adaptive Body Limit: Standard Reputation",
		Disposition: DispositionMiddleware, Replacement: replacementMaxBody,
		Why: whyPerRequestBodyLimit,
	},
	{
		ID: "1900402", Name: "Adaptive Body Limit: Low Reputation",
		Disposition: DispositionMiddleware, Replacement: replacementMaxBody,
		Why: whyPerRequestBodyLimit,
	},
	{
		ID: "1910000", Name: "IP Reputation Flagging",
		Disposition: DispositionResolver, Replacement: "ReputationResolver",
		Why: "the flag travelled as the X-Gateon-IP-Reputation-Block request header; it now crosses as a resolver value that no client can write.",
	},
	{
		ID: "1900200", Name: "gRPC Content-Type Compatibility",
		Disposition: DispositionNative, Replacement: replacementNoneNeeded,
		Why: "it widened a CRS content-type allowlist that gwaf does not have; there is no protocol-conformance rule left to appease.",
	},
	{
		ID: "1900201", Name: "gRPC Body Access Control",
		Disposition: DispositionNative, Replacement: "gwaf text-run extraction",
		Why: "it disabled body inspection for gRPC to avoid false positives on binary protobuf; gwaf inspects only printable runs inside binary payloads, so the body stays inspected.",
	},
	{
		ID: "1100013", Name: "Log4Shell Protection",
		Disposition: DispositionMerged, Replacement: "rule 1151000",
		Why: "the same detection as 1151000, which covers strictly more targets.",
	},
	{
		ID: "1120010", Name: "DDoS: Too Many Headers",
		Disposition: DispositionEngine, Replacement: "gwaf Limits.MaxHeaders",
		Why: "counting collection members needs a count operator gwaf does not ship; the engine enforces a header ceiling directly.",
	},
	{
		ID: "1120011", Name: "DDoS: Header Key Length Limit",
		Disposition: DispositionMiddleware, Replacement: "protocol middleware",
		Why: "a bound on header-name length is a protocol concern and is enforced before the engine runs.",
	},
	{
		ID: "1120012", Name: "DDoS: HTTP Request Smuggling (CL)",
		Disposition: DispositionNative, Replacement: "gwaf framing analysis",
		Why: "gwaf detects conflicting Content-Length and Transfer-Encoding framing in the engine and refuses the request as undecidable.",
	},
	{
		ID: "1150002", Name: "API: Multiple Content-Type Headers",
		Disposition: DispositionMiddleware, Replacement: "protocol middleware",
		Why: "counting duplicate headers needs a count operator gwaf does not ship; it is enforced before the engine runs.",
	},
}

// RetirementByID indexes Retirements for dashboard lookups, so a threat record
// referencing an ID that no longer exists can explain itself instead of
// rendering a bare number.
func RetirementByID(id string) (Retirement, bool) {
	for _, r := range Retirements {
		if r.ID == id {
			return r, true
		}
	}
	return Retirement{}, false
}
