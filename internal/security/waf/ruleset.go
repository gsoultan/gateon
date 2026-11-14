// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"strconv"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/ruleset/leaks"
	"github.com/gsoultan/gwaf/ruleset/signatures"
	"github.com/gsoultan/gwaf/types"
)

// This is gateon's built-in ruleset: the rules it loads beside gwaf's core.
// They are compiled into the binary rather than stored as rows: a default rule
// is code gateon ships and tests, not data an operator authored, and keeping it
// in the database meant every install carried its own drifting copy of it.
//
// # What gateon owns here, and what it does not
//
// Detection belongs to gwaf (ADR 0092). A rule that decides "is this request an
// attack?" from the request alone is defined in gwaf's ruleset/signatures or
// ruleset/leaks, and an entry here only names it with `from` and adds what is
// gateon's to decide: the rule ID an install's threat history and exceptions
// already use, the category switch it answers to, the paranoia level it loads
// at, and what a match does. Its operator, targets, transforms, phase, severity,
// confidence and message come from gwaf, so a detection bug is fixed there and
// arrives here by a version bump. TestNoDetectionIsDefinedInGateon holds the
// line.
//
// The few entries defined in full are the ones gwaf's scope rule keeps out of
// the library: a decision gateon made and hands the engine through a resolver
// (reputation, the WordPress admin allowlist, the AMP origin check), and site
// policy that is not attack detection at all (gambling content, non-browser
// clients, path depth).
//
// Rule IDs are unchanged from the SecLang originals so that threat history,
// dashboards and any operator-written exception keep referring to the same
// detection across both migrations.
//
// # Confidence and paranoia level must agree
//
// gwaf drops any rule below the configured minimum confidence at compile time,
// and gateon derives that minimum from the paranoia level. So a rule's
// Confidence and its PL are two statements about the same thing and have to
// agree, or a rule is loaded by gateon and then silently discarded by gwaf.
// TestParanoiaLevelAgreesWithConfidence enforces it.
//
// PL1 => High or Certain: rare, well-understood false positives.
// PL2 => Medium: fires on unusual but legitimate traffic often enough to matter.
// PL3 => Low: a heuristic that needs tuning against real traffic.

// Rule categories. They name the family a rule belongs to and are the unit
// the per-family configuration switches turn on and off, so they are
// constants rather than strings repeated across the corpus: a typo in one
// would silently put a rule in a category nothing can disable.
const (
	CategoryContentScanner = "Content-Scanner"
	CategoryInjection      = "Injection"
	CategoryReputation     = "Reputation"
	CategoryRCE            = "RCE"
	CategorySQLi           = "SQLi"
	CategoryXSS            = "XSS"
	CategoryExploit        = "Exploit"
	CategoryProtocol       = "Protocol"
	CategoryMalware        = "Malware"
	CategoryRansomware     = "Ransomware"
	CategoryWordPress      = "WordPress"
	CategoryScanner        = "Scanner"
	CategoryDLP            = "DLP"
)

// Rule tags. Like categories they are a selection unit — the per-family
// switches disable by tag as well — so they are named rather than repeated.
const (
	TagAttackSqli    = "attack-sqli"
	TagAttackXss     = "attack-xss"
	TagAttackRce     = "attack-rce"
	TagAttackGeneric = "attack-generic"
	TagScanner       = "scanner"
	TagMalware       = "malware"
	TagRansomware    = "ransomware"
	TagDlp           = "dlp"
	TagWpScan        = "wp_scan"
	TagReputation    = "reputation"
	TagFileupload    = "fileupload"
	TagPhp           = "php"
	TagJava          = "java"
	TagProtocol      = "protocol"
	TagRce           = "rce"

	// TagDlpInbound marks the request-phase half of data-leak detection. It is
	// its own tag because the two directions answer different questions and an
	// operator may well want one without the other: a card number in a response
	// is a leak, the same card number in a request is a customer paying for
	// something.
	TagDlpInbound = "dlp-inbound"

	// TagCompliance marks the rules a compliance regime asks for by name: card
	// numbers and national identifiers.
	TagCompliance = "compliance"

	// TagLeakage marks structural disclosure — a stack trace, a framework error
	// page, a database error — as opposed to a credential. The distinction is a
	// selection unit: the two groups sit at different paranoia levels because a
	// site may legitimately serve the former and never the latter.
	TagLeakage = "leakage"
)

// spec is the compact form of a gateon rule. It exists because a rules.Rule
// literal repeated across the corpus is mostly punctuation; this keeps it
// readable as a table so a reviewer can see the whole ruleset at once.
type spec struct {
	id uint32

	// from names the gwaf rule this entry takes its detection from. When set,
	// phase, targets, xform, op, severity, conf and msg are filled from that
	// rule by resolveSpecs and must not be written here; conf alone may be set,
	// to hold a rule at the tier this corpus has always loaded it at.
	from types.RuleID

	phase    types.Phase
	targets  []types.Target
	xform    []rules.Transform
	op       rules.Operator
	status   int // 0 blocks with the policy default
	severity types.Severity
	conf     types.Confidence
	pl       int
	msg      string
	category string
	tags     []string

	// action overrides the default of blocking. Nil keeps every existing rule
	// exactly as it was: the corpus is a security control, and a refactor that
	// quietly turned a block into a log would be the worst kind of silent
	// change. Set it only where not blocking is the deliberate design — inbound
	// secret detection, where refusing the request would throw away what a user
	// typed and teach them to route around the gateway.
	action rules.Action
}

// rule renders the spec as a gwaf rule.
func (s spec) rule() rules.Rule {
	action := rules.Block
	if s.status != 0 {
		action = rules.BlockWithStatus(s.status)
	}
	if s.action != nil {
		action = s.action
	}
	return rules.Rule{
		ID:         types.RuleID(s.id),
		Phase:      s.phase,
		Targets:    s.targets,
		Transforms: s.xform,
		Op:         s.op,
		Actions:    []rules.Action{action},
		Severity:   s.severity,
		Confidence: s.conf,
		Msg:        s.msg,
		Tags:       s.tags,
	}
}

// Target groups for the few rules defined here. The rules that take their
// detection from gwaf take their targets from it too.
var (
	tPath = []types.Target{{Kind: types.TargetRequestPath}}

	tArgsHeadersURI = []types.Target{
		{Kind: types.TargetArgs},
		{Kind: types.TargetRequestHeaders},
		{Kind: types.TargetRequestURI},
	}

	// Transform chains. gwaf records values exactly as they arrived and makes
	// normalization the rule's explicit choice, so a rule that does not ask for
	// a decode is bypassable by percent-encoding a single character.
	norm    = []rules.Transform{transform.URLDecode, transform.Lowercase}
	decoded = []rules.Transform{transform.URLDecode}
)

func header(name string) []types.Target {
	return []types.Target{{Kind: types.TargetRequestHeaders, Name: name}}
}

// resolved names a value gateon supplies through a rules.Resolver rather than
// one gwaf read off the request. See resolver.go.
func resolved(name string) []types.Target {
	return []types.Target{{Kind: types.TargetResolved, Name: name}}
}

// DefaultRules returns gateon's first-party ruleset filtered to the given
// paranoia level. Rules above the level are not compiled, so they cost nothing.
func DefaultRules(paranoiaLevel int) rules.Set {
	if paranoiaLevel < 1 {
		paranoiaLevel = 1
	}
	set := make(rules.Set, 0, len(defaultSpecs))
	for _, s := range defaultSpecs {
		if s.pl <= paranoiaLevel {
			set = append(set, s.rule())
		}
	}
	return set
}

// RuleInfo describes one built-in rule to callers outside this package.
//
// It exists because the corpus is a table of unexported specs, and the
// dashboard, the telemetry recorder and the API all need to say what a rule ID
// means without being able to run it.
type RuleInfo struct {
	ID         uint32
	Msg        string
	Category   string
	Tags       []string
	Severity   types.Severity
	Confidence types.Confidence
	Phase      types.Phase

	// ParanoiaLevel is the level at or above which the rule is loaded.
	ParanoiaLevel int

	// From is the gwaf rule this one takes its detection from, and zero for a
	// rule whose detection is written in gateon (ADR 0092).
	From types.RuleID

	// Action is what a match does: "block", or "log" for a rule that records
	// the match and lets the request through.
	Action string
}

func (s spec) info() RuleInfo {
	action := rules.Block.Name()
	if s.action != nil {
		action = s.action.Name()
	}
	return RuleInfo{
		ID:            s.id,
		Msg:           s.msg,
		Category:      s.category,
		Tags:          s.tags,
		Severity:      s.severity,
		Confidence:    s.conf,
		Phase:         s.phase,
		ParanoiaLevel: s.pl,
		From:          s.from,
		Action:        action,
	}
}

// RuleCatalog describes gateon's built-in rules.
//
// The rules themselves are compiled into the binary, so this is how an operator
// discovers what is running without a table of rows to read.
func RuleCatalog() []RuleInfo {
	out := make([]RuleInfo, 0, len(defaultSpecs))
	for _, s := range defaultSpecs {
		out = append(out, s.info())
	}
	return out
}

// LookupRule returns the built-in rule with this ID.
func LookupRule(id uint32) (RuleInfo, bool) {
	for _, s := range defaultSpecs {
		if s.id == id {
			return s.info(), true
		}
	}
	return RuleInfo{}, false
}

// RepeatsEarlierDecision reports whether a built-in rule refuses on a decision
// the gateway already made rather than on anything the request carries: the
// reputation family, 1910001 (a feed lists the address) and 1910002 (the
// client's own reputation fell below 20). Such a refusal is recorded and held
// against nobody, as the reputation blocker's and the feed's own are (ADR
// 0055): held, every refused retry was a new penalty, and the third blocked the
// client's browser build on its whole network. This is the one place that says
// which rules those are; a rule joins by its category.
func RepeatsEarlierDecision(id uint32) bool {
	info, ok := LookupRule(id)
	return ok && info.Category == CategoryReputation
}

// defaultSpecs is the corpus every consumer reads: builtinSpecs with each
// entry's detection filled in from gwaf.
var defaultSpecs = resolveSpecs(builtinSpecs)

// resolveSpecs fills every entry that names a gwaf rule from that rule.
//
// An entry naming a rule gwaf does not ship panics, at package initialisation,
// the way rx.MustNew does for a pattern that does not compile: it is a
// programming error that would otherwise leave a rule in the table that
// inspects nothing, and a WAF missing a rule it lists is the failure that must
// not be silent.
func resolveSpecs(table []spec) []spec {
	source := make(map[types.RuleID]rules.Rule)
	for _, r := range append(signatures.All(), leaks.All()...) {
		source[r.ID] = r
	}
	out := make([]spec, 0, len(table))
	for _, s := range table {
		if s.from != 0 {
			r, ok := source[s.from]
			if !ok {
				panic("waf: built-in rule " + strconv.FormatUint(uint64(s.id), 10) +
					" names gwaf rule " + strconv.FormatUint(uint64(s.from), 10) + ", which gwaf does not ship")
			}
			s.phase, s.targets, s.xform, s.op = r.Phase, r.Targets, r.Transforms, r.Op
			s.severity, s.msg = r.Severity, r.Msg
			if s.conf == 0 {
				s.conf = r.Confidence
			}
		}
		out = append(out, s)
	}
	return out
}

// builtinSpecs is the table as written. Ordering is by category for
// readability; gwaf sorts by (phase, ID) at compile time, so source order does
// not affect evaluation.
var builtinSpecs = []spec{
	// ------------------------------------------------------ defined by gateon
	// What follows is not attack detection from the request alone, which is
	// why it is not in gwaf: three decisions gateon makes and hands the engine
	// through a resolver, and three statements of site policy.
	{
		id: 1210001, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform: norm,
		op: op.ContainsAny("betting", "gambling", "casino", "slot machine", "poker",
			"sportsbook", "jackpot", "lottery", "bookmaker", "wagering",
			"baccarat", "blackjack", "roulette"),
		severity: types.SeverityWarning, conf: types.Medium, pl: 2,
		msg: "Online gambling content detected", category: CategoryContentScanner,
		tags: []string{"gambling", "content"},
	},
	// The reputation bucket arrives through a resolver, not a request header.
	// Under Coraza these rules read X-Gateon-Reputation, a header gateon wrote
	// into the request and then had to strip from client input on every request
	// to stop a client asserting its own reputation. The resolver removes the
	// vector rather than mitigating it.
	{
		id: 1910001, phase: types.PhaseRequestHeaders, targets: resolved(ResolverReputation),
		op:       op.Equals(ReputationBlocked),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "IP reputation block (external feed)", category: CategoryReputation,
		tags: []string{TagReputation},
	},
	{
		id: 1910002, phase: types.PhaseRequestHeaders, targets: resolved(ResolverReputation),
		op:       op.Equals(ReputationHostile),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Internal behaviour reputation block", category: CategoryReputation,
		tags: []string{TagReputation},
	},
	{
		id: 1150000, phase: types.PhaseRequestHeaders, targets: tPath,
		xform:    decoded,
		op:       NewSegmentCount("excessive-path-depth", '/', 15),
		status:   403,
		severity: types.SeverityWarning, conf: types.High, pl: 1,
		msg: "Excessive path depth", category: CategoryProtocol,
		tags: []string{TagProtocol, "dos"},
	},
	// The chained "!@ipMatch %{tx.allowed_admin_ips}" second clause is gone:
	// gwaf has no rule chaining and no negation. The allowlist is now decided by
	// gateon and delivered as a resolved bucket, which also means the comparison
	// happens against the connection's real peer rather than a SecLang variable.
	{
		id: 1100001, phase: types.PhaseRequestHeaders, targets: resolved(ResolverAdminAccess),
		op:       op.Equals(AdminAccessWPAdmin),
		status:   403,
		severity: types.SeverityError, conf: types.High, pl: 1,
		msg: "WordPress admin access from a non-allowlisted address", category: CategoryWordPress,
		tags: []string{TagWpScan},
	},
	{
		id: 1100002, phase: types.PhaseRequestHeaders, targets: resolved(ResolverAdminAccess),
		op:       op.Equals(AdminAccessWPLogin),
		status:   403,
		severity: types.SeverityError, conf: types.High, pl: 1,
		msg: "WordPress login from a non-allowlisted address", category: CategoryWordPress,
		tags: []string{TagWpScan},
	},
	{
		// The chained "!@rx ^(/api/|/v[0-9]/)" exemption is now expressed as
		// path exceptions in DefaultExceptions, which is gwaf's mechanism for
		// "this rule does not apply here".
		id: 1110003, phase: types.PhaseRequestHeaders, targets: header("User-Agent"),
		xform: norm,
		op: op.ContainsAny("python-requests", "go-http-client", "libwww-perl",
			"urllib", "postman", "insomnia"),
		status:   403,
		severity: types.SeverityNotice, conf: types.Low, pl: 3,
		msg: "Automated non-browser client", category: CategoryScanner,
		tags: []string{TagScanner, "bot"},
	},
	{
		// The original compared ARGS:__amp_source_origin against a pattern built
		// from %{REQUEST_HEADERS:Host}. A rule operator sees one value and knows
		// nothing about any other, so a cross-value comparison like this cannot
		// be a rule; gateon performs it and delivers the verdict.
		id: 1180000, phase: types.PhaseRequestHeaders, targets: resolved(ResolverOrigin),
		op:       op.Equals(OriginAMPMismatch),
		status:   403,
		severity: types.SeverityError, conf: types.High, pl: 1,
		msg: "AMP source origin spoofing attempt", category: CategoryExploit,
		tags: []string{"attack-amp"},
	},

	// ------------------------------------------------- detection, from gwaf
	// Request signatures. gateon decides the ID, the category switch, the
	// paranoia level and the status; gwaf decides what matches.
	{id: 1210002, from: signatures.IDScriptObfuscation, pl: 1, category: CategoryContentScanner,
		tags: []string{"javascript", TagMalware}},
	{id: 1210003, from: signatures.IDPHPKeyword, pl: 1, category: CategoryInjection,
		tags: []string{TagPhp, "injection"}},
	{id: 1210004, from: signatures.IDScriptInUserContent, pl: 1, category: CategoryInjection,
		tags: []string{TagFileupload, TagRce}},
	{id: 1100010, from: signatures.IDGoCode, status: 403, pl: 1, category: CategoryRCE,
		tags: []string{TagRce, "golang"}},
	{id: 1100011, from: signatures.IDJavaClass, status: 403, pl: 1, category: CategoryRCE,
		tags: []string{TagRce, TagJava}},
	{id: 1100016, from: signatures.IDNodeCode, status: 403, pl: 1, category: CategoryRCE,
		tags: []string{TagRce, "nodejs"}},
	{id: 1100015, from: signatures.IDSensitiveFileHeader, status: 403, pl: 1, category: CategoryInjection,
		tags: []string{"lfi"}},
	{id: 1100014, from: signatures.IDShellshock, status: 403, pl: 1, category: CategoryRCE,
		tags: []string{TagRce, "cve-2014-6271"}},
	{id: 1151000, from: signatures.IDLog4Shell, status: 403, pl: 1, category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2021-44228"}},
	{id: 1151001, from: signatures.IDSpring4Shell, status: 403, pl: 1, category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2022-22965"}},
	{id: 1151002, from: signatures.IDCommandSeparator, status: 403, pl: 2, category: CategoryRCE,
		tags: []string{TagAttackRce}},
	{id: 1151003, from: signatures.IDTraversalArgName, status: 403, pl: 1, category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2023-50164"}},
	{id: 1151005, from: signatures.IDGoAnywhere, status: 403, pl: 1, category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2023-0669"}},
	{id: 1151006, from: signatures.IDText4Shell, status: 403, pl: 1, category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2022-42889"}},
	{id: 1151007, from: signatures.IDFollina, status: 403, pl: 1, category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2022-30190"}},
	{id: 1140000, from: signatures.IDSQLTimeDelay, status: 403, pl: 1, category: CategorySQLi,
		tags: []string{TagAttackSqli}},
	{id: 1140002, from: signatures.IDSQLSchemaEnum, status: 403, pl: 1, category: CategorySQLi,
		tags: []string{TagAttackSqli}},
	{id: 1140001, from: signatures.IDSQLTautology, status: 403, pl: 2, category: CategorySQLi,
		tags: []string{TagAttackSqli}},
	{id: 1140003, from: signatures.IDMOVEitHeader, status: 403, pl: 1, category: CategorySQLi,
		tags: []string{TagAttackSqli, "cve-2023-34362"}},
	{id: 1141000, from: signatures.IDXSSTagOrHandler, status: 403, pl: 1, category: CategoryXSS,
		tags: []string{TagAttackXss}},
	{id: 1141002, from: signatures.IDXSSObfuscated, status: 403, pl: 1, category: CategoryXSS,
		tags: []string{TagAttackXss}},
	{id: 1160000, from: signatures.IDNoSQLOperator, status: 403, pl: 2, category: CategoryInjection,
		tags: []string{"attack-nosql"}},
	{id: 1170000, from: signatures.IDPrototypePollution, status: 403, pl: 1, category: CategoryExploit,
		tags: []string{TagAttackGeneric}},
	{id: 1170001, from: signatures.IDPrototypeChain, status: 403, pl: 2, category: CategoryExploit,
		tags: []string{TagAttackGeneric}},
	// Header phase only in gwaf, and deliberately so: a body-phase twin would
	// match every binary upload, because a PNG carries NULs in its first eight
	// bytes. TestNullByteStaysOutOfTheBodyPhase pins this decision.
	{id: 1150001, from: signatures.IDNullByte, status: 403, pl: 1, category: CategoryProtocol,
		tags: []string{TagAttackGeneric}},
	{id: 1150003, from: signatures.IDInternalAddress, status: 403, pl: 2, category: CategoryProtocol,
		tags: []string{"attack-ssrf"}},
	{id: 1100004, from: signatures.IDUploadExecutableExt, status: 403, pl: 1, category: CategoryMalware,
		tags: []string{TagMalware, TagFileupload}},
	{id: 1100005, from: signatures.IDPHPOpenTag, status: 403, pl: 1, category: CategoryMalware,
		tags: []string{TagMalware, TagRce}},
	{id: 1100006, from: signatures.IDPDFJavaScript, status: 403, pl: 1, category: CategoryMalware,
		tags: []string{TagMalware, TagFileupload}},
	{id: 1100007, from: signatures.IDRansomwareExt, status: 403, pl: 1, category: CategoryRansomware,
		tags: []string{TagRansomware}},
	{id: 1100008, from: signatures.IDWebShellName, status: 403, pl: 1, category: CategoryMalware,
		tags: []string{TagMalware, TagRce}},
	{id: 1100009, from: signatures.IDRansomNote, status: 403, pl: 1, category: CategoryRansomware,
		tags: []string{TagRansomware}},
	{id: 1142000, from: signatures.IDRansomKeywords, status: 403, pl: 3, category: CategoryRansomware,
		tags: []string{TagRansomware}},
	{id: 1190000, from: signatures.IDCryptoMiner, status: 403, pl: 1, category: CategoryExploit,
		tags: []string{"attack-malware"}},
	{id: 1100003, from: signatures.IDWPPluginPHP, status: 403, pl: 1, category: CategoryWordPress,
		tags: []string{TagWpScan}},
	{id: 1100012, from: signatures.IDWPEnumeration, status: 403, pl: 1, category: CategoryWordPress,
		tags: []string{TagWpScan}},
	{id: 1110000, from: signatures.IDScannerUserAgent, status: 403, pl: 1, category: CategoryScanner,
		tags: []string{TagScanner, "recon"}},
	{id: 1110001, from: signatures.IDScannerHeader, status: 403, pl: 1, category: CategoryScanner,
		tags: []string{TagScanner}},
	{id: 1110002, from: signatures.IDWebShellProbe, status: 403, pl: 1, category: CategoryScanner,
		tags: []string{TagScanner, TagRce}},
	{id: 1110004, from: signatures.IDSensitiveFileProbe, status: 403, pl: 1, category: CategoryScanner,
		tags: []string{TagScanner, "recon"}},

	// Held at Medium, and so at PL2, where this corpus has always loaded them.
	// gwaf measured both above its Medium false-positive ceiling on its benign
	// corpus (1.5% and 1.07% against 1%) and declares them Low, which would
	// move them to PL3 and take them away from every enterprise-tier install.
	// Whether to follow gwaf is a decision about a default, and a default is not
	// changed as a side effect of moving a rule (CLAUDE.md, "when profiles
	// conflict"). The override is the visible record that the two disagree.
	{id: 1151004, from: signatures.IDExpressionLanguage, status: 403, conf: types.Medium, pl: 2, category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2022-22947"}},
	{id: 1151008, from: signatures.IDShellBuiltin, status: 403, conf: types.Medium, pl: 2, category: CategoryRCE,
		tags: []string{TagAttackRce}},

	// Shellshock in a request body. Certain, and still PL2: gwaf can extract
	// no literal from the pattern, so the rule runs on every body in its phase.
	// PL1 budgets a fixed number of such rules (TestUnconditionalRulesAreBudgeted)
	// and already spends them. Query-string Shellshock is caught at PL1 by
	// 1100014; only the body-borne form needs PL2.
	{id: 1151009, from: signatures.IDShellshockBody, status: 403, pl: 2, category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2014-6271"}},

	// Credentials and regulated data in a response. PL1, because response
	// inspection is already opt-in and enterprise-tier: gating these behind the
	// paranoia level as well would mean an operator turns DLP on and nothing
	// happens. The opt-in is the gate. Twilio alone is PL2, as gwaf declares it
	// Medium: its pattern is the one in the group with a plausible false
	// positive, and it cannot be prefiltered.
	{id: 1130000, from: leaks.IDCardNumber, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp, TagCompliance}},
	{id: 1130001, from: leaks.IDUSSocialSecurity, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp, TagCompliance}},
	{id: 1130002, from: leaks.IDPrivateKey, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130003, from: leaks.IDAWSAccessKey, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130004, from: leaks.IDGoogleAPIKey, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130005, from: leaks.IDSlackWebhook, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130006, from: leaks.IDGitHubPAT, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130007, from: leaks.IDGoogleOAuthSecret, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130008, from: leaks.IDStripeLiveKey, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp, TagCompliance}},
	{id: 1130009, from: leaks.IDGitHubToken, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130010, from: leaks.IDGitHubFinePAT, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130011, from: leaks.IDOpenAIKey, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130012, from: leaks.IDAnthropicKey, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130013, from: leaks.IDSlackToken, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130014, from: leaks.IDSendGridKey, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130015, from: leaks.IDTwilioSID, status: 403, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130016, from: leaks.IDNPMToken, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130017, from: leaks.IDPyPIToken, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130018, from: leaks.IDGCPServiceAccount, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130019, from: leaks.IDAzureStorageKey, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130020, from: leaks.IDDatabaseURI, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},
	{id: 1130021, from: leaks.IDPuTTYKey, status: 403, pl: 1, category: CategoryDLP,
		tags: []string{TagDlp}},

	// Structural disclosure: a stack trace or a database error. PL2, because a
	// site whose job is to display stack traces serves them legitimately.
	// Enterprise tier raises the paranoia level to 2 and gets these; a
	// standard-tier install that opts into DLP alone stays at PL1 and gets the
	// credential rules only. TestDLPStructuralRulesAreNotPL1 pins it.
	{id: 1130022, from: leaks.IDGoPanic, status: 403, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage}},
	{id: 1130023, from: leaks.IDPythonTraceback, status: 403, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage}},
	{id: 1130024, from: leaks.IDJavaStackTrace, status: 403, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage}},
	{id: 1130025, from: leaks.IDPHPError, status: 403, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage, TagPhp}},
	{id: 1130026, from: leaks.IDDotNetException, status: 403, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage}},
	{id: 1130027, from: leaks.IDRubyBacktrace, status: 403, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage}},
	{id: 1130028, from: leaks.IDDatabaseError, status: 403, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage}},

	// The credential detectors pointed at the request. Two deliberate policy
	// differences from the response rules above.
	//
	// They log rather than block. Refusing a POST because it contains a secret
	// throws away what the user typed and teaches them to route around the
	// gateway, which is a worse outcome than the leak: now nobody can see it at
	// all. The finding reaches the Security Hub through the same path every
	// other match does.
	//
	// And PL2, which is where enterprise tier sits: the detectors are Certain,
	// but scanning every request body is a cost a minimal deployment should not
	// pay silently.
	{id: 1131000, from: leaks.IDInboundPrivateKeyPEM, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131001, from: leaks.IDInboundAWSAccessKey, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131002, from: leaks.IDInboundStripeLiveKey, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131003, from: leaks.IDInboundGitHubPAT, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131004, from: leaks.IDInboundGitHubToken, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131005, from: leaks.IDInboundGitHubFinePAT, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131006, from: leaks.IDInboundOpenAIKey, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131007, from: leaks.IDInboundAnthropicKey, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131008, from: leaks.IDInboundSlackToken, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131009, from: leaks.IDInboundSlackWebhook, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131010, from: leaks.IDInboundGoogleAPIKey, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131011, from: leaks.IDInboundGoogleOAuth, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131012, from: leaks.IDInboundGCPServiceAcct, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131013, from: leaks.IDInboundAzureStorageKey, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131014, from: leaks.IDInboundSendGridKey, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131015, from: leaks.IDInboundNPMToken, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131016, from: leaks.IDInboundPyPIToken, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131017, from: leaks.IDInboundPuTTYKey, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
	{id: 1131018, from: leaks.IDInboundDBURICreds, action: rules.Log, pl: 2, category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound}},
}

// DefaultExceptions carries the narrow carve-outs that used to be expressed as
// SecLang rule chains. gwaf has no chaining, and an exception is the mechanism
// it offers for "this detection does not apply here".
func DefaultExceptions() []rules.Exception {
	// Rule 1110003 flags non-browser user agents, which is a useful signal on a
	// site but meaningless on an API: every legitimate client there is a
	// library. The original expressed this as a chained negative match on
	// ^(/api/|/v[0-9]/); Exception.Path takes a prefix, so the versioned form
	// is enumerated.
	ex := []rules.Exception{{
		RuleID: 1110003,
		Path:   "/api/*",
		Note:   "automated clients are the expected caller on the API surface",
	}}
	for _, v := range []string{"/v0/*", "/v1/*", "/v2/*", "/v3/*", "/v4/*",
		"/v5/*", "/v6/*", "/v7/*", "/v8/*", "/v9/*"} {
		ex = append(ex, rules.Exception{
			RuleID: 1110003,
			Path:   v,
			Note:   "automated clients are the expected caller on a versioned API",
		})
	}
	return ex
}
