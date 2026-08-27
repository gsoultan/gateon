// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/rules/op/rx"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/types"
)

// This is gateon's first-party ruleset, converted from the SecLang directives
// that used to be seeded into the waf_rules table. They are compiled into the
// binary rather than stored as rows: a default rule is code gateon ships and
// tests, not data an operator authored, and keeping it in the database meant
// every install carried its own drifting copy of it.
//
// Rule IDs are unchanged from the SecLang originals so that threat history,
// dashboards and any operator-written exception keep referring to the same
// detection across the migration.
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

	// TagLeakage marks structural disclosure — a stack trace, a framework error
	// page, a database error — as opposed to a credential. The distinction is a
	// selection unit: the two groups sit at different paranoia levels because a
	// site may legitimately serve the former and never the latter.
	TagLeakage = "leakage"
)

// Credential detectors, named because both directions use them.
//
// A response leaking an AWS key and a request carrying one are the same string
// found in two places, and writing the pattern twice is how the two copies come
// to disagree — one gets a new prefix, the other does not, and the gap is
// invisible until something walks out through it. One operator, two rules.
//
// Operators are stateless and already shared across every transaction
// evaluating a rule; sharing one across two rules is the same property.
var (
	opPrivateKeyPEM   = rx.MustNew(`-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`)
	opAWSAccessKey    = rx.MustNew(`\bAKIA[0-9A-Z]{16}\b`)
	opGoogleAPIKey    = rx.MustNew(`AIza[0-9A-Za-z\-_]{35}`)
	opSlackWebhook    = op.Contains("https://hooks.slack.com/services/")
	opGitHubPAT       = rx.MustNew(`ghp_[a-zA-Z0-9]{36}`)
	opGoogleOAuth     = rx.MustNew(`GOCSPX-[a-zA-Z0-9\-_]{28}`)
	opStripeLiveKey   = rx.MustNew(`\b[sr]k_live_[0-9a-zA-Z]{24,}`)
	opGitHubToken     = rx.MustNew(`\bgh[ousr]_[A-Za-z0-9]{36}\b`)
	opGitHubFinePAT   = rx.MustNew(`\bgithub_pat_[A-Za-z0-9_]{82}\b`)
	opOpenAIKey       = rx.MustNew(`\bsk-[A-Za-z0-9_-]{10,}T3BlbkFJ[A-Za-z0-9_-]{10,}`)
	opAnthropicKey    = rx.MustNew(`\bsk-ant-[a-z0-9]{3,}-[A-Za-z0-9_-]{80,}`)
	opSlackToken      = rx.MustNew(`\bxox[baprse]-[0-9A-Za-z-]{10,}`)
	opSendGridKey     = rx.MustNew(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`)
	opNPMToken        = rx.MustNew(`\bnpm_[A-Za-z0-9]{36}\b`)
	opPyPIToken       = rx.MustNew(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`)
	opGCPServiceAcct  = rx.MustNew(`"type"\s*:\s*"service_account"`)
	opAzureStorageKey = rx.MustNew(`\bAccountKey=[A-Za-z0-9+/]{86}==`)
	opPuTTYKey        = op.Contains("PuTTY-User-Key-File-")
	opDBURICreds      = rx.MustNew(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|clickhouse)` +
		`://[^\s:@/]{1,64}:[^\s:@/]{1,128}@`)
)

// spec is the compact form of a gateon rule. It exists because a rules.Rule
// literal repeated 57 times is mostly punctuation; this keeps the corpus
// readable as a table so a reviewer can see the whole ruleset at once.
type spec struct {
	id       uint32
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

// Target groups, named after the SecLang collections they replace so the
// conversion stays auditable against the original directives.
var (
	tArgs     = []types.Target{{Kind: types.TargetArgs}}
	tArgNames = []types.Target{{Kind: types.TargetArgNames}}

	// FILES_NAMES: the client-supplied name of an uploaded file. It is its own
	// target rather than an argument whose key happens to end in ".filename",
	// so a rule about executable uploads cannot also block "?page=index.php".
	tFileNames   = []types.Target{{Kind: types.TargetFileNames}}
	tURI         = []types.Target{{Kind: types.TargetRequestURI}}
	tPath        = []types.Target{{Kind: types.TargetRequestPath}}
	tRespBody    = []types.Target{{Kind: types.TargetResponseBody}}
	tHeaderNames = []types.Target{{Kind: types.TargetRequestHeaderNames}}

	// ARGS|REQUEST_HEADERS|REQUEST_URI, the most common gateon target set.
	tArgsHeadersURI = []types.Target{
		{Kind: types.TargetArgs},
		{Kind: types.TargetRequestHeaders},
		{Kind: types.TargetRequestURI},
	}

	// ARGS|REQUEST_BODY. gwaf merges parsed body arguments into TargetArgs, so
	// the raw body target is added only for payloads that are not key/value
	// structured.
	tArgsBody = []types.Target{
		{Kind: types.TargetArgs},
		{Kind: types.TargetRequestBody},
	}

	// Some payloads arrive as the parameter *name* rather than its value —
	// Spring4Shell and prototype pollution both work that way, and the SecLang
	// originals inspected only ARGS, so they would have missed the canonical
	// exploit for the CVE they were named after.
	tArgsNamesBody = []types.Target{
		{Kind: types.TargetArgs},
		{Kind: types.TargetArgNames},
		{Kind: types.TargetRequestBody},
	}

	tArgsHeadersURIBody = []types.Target{
		{Kind: types.TargetArgs},
		{Kind: types.TargetRequestHeaders},
		{Kind: types.TargetRequestURI},
		{Kind: types.TargetRequestBody},
	}

	// Transform chains. There are deliberately only two.
	//
	// ModSecurity handed rules an already-percent-decoded ARGS collection, so
	// the SecLang originals could match "<script" without asking for anything.
	// gwaf records values exactly as they arrived and makes normalization the
	// rule's explicit choice, which is the safer default but means every
	// converted rule has to state the decode it used to get for free. Without
	// it each one is bypassable by percent-encoding a single character.
	//
	// Keeping the corpus to two chains is also why it is cheap: a chain is
	// materialized once per value, so the cost that matters is the number of
	// distinct chains, not the number of rules using them.
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
}

// RuleCatalog describes gateon's built-in rules.
//
// The rules themselves are compiled into the binary, so this is how an operator
// discovers what is running without a table of rows to read.
func RuleCatalog() []RuleInfo {
	out := make([]RuleInfo, 0, len(defaultSpecs))
	for _, s := range defaultSpecs {
		out = append(out, RuleInfo{
			ID:            s.id,
			Msg:           s.msg,
			Category:      s.category,
			Tags:          s.tags,
			Severity:      s.severity,
			Confidence:    s.conf,
			Phase:         s.phase,
			ParanoiaLevel: s.pl,
		})
	}
	return out
}

// LookupRule returns the built-in rule with this ID.
func LookupRule(id uint32) (RuleInfo, bool) {
	for _, s := range defaultSpecs {
		if s.id == id {
			return RuleInfo{
				ID:            s.id,
				Msg:           s.msg,
				Category:      s.category,
				Tags:          s.tags,
				Severity:      s.severity,
				Confidence:    s.conf,
				Phase:         s.phase,
				ParanoiaLevel: s.pl,
			}, true
		}
	}
	return RuleInfo{}, false
}

// defaultSpecs is the corpus. Ordering is by category for readability; gwaf
// sorts by (phase, ID) at compile time, so source order does not affect
// evaluation.
var defaultSpecs = []spec{
	// ---------------------------------------------------------------- content
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
	{
		id: 1210002, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform: norm,
		op: op.ContainsAny("string.fromcharcode", "unescape(", "%u00", "eval(atob(",
			"navigator.sendbeacon", "new websocket(", "document.write(",
			"document.createelement('script')"),
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Malicious JavaScript detected", category: CategoryContentScanner,
		tags: []string{"javascript", TagMalware},
	},
	{
		id: 1210003, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform: norm,
		op: op.ContainsAny("<?php", "file_get_contents(", "shell_exec(", "passthru(",
			"base64_decode(", "$_get", "$_post", "$_request", "$_server",
			"$_cookie", "$_files"),
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "PHP vulnerability exploit attempt", category: CategoryInjection,
		tags: []string{TagPhp, "injection"},
	},
	{
		id: 1210004, phase: types.PhaseRequestBody, targets: tPath,
		xform: norm,
		// A script *inside a directory whose purpose is user-supplied content*.
		//
		// Both halves are required. The extension alone is not evidence of
		// anything: WordPress is PHP, Django serves .py-backed routes, and
		// plenty of estates still run .jsp and .cgi — a rule matching only the
		// suffix refuses every one of those applications at the front door,
		// which is an outage dressed as a security control. The upload
		// directory alone is equally ordinary, since every site serves images
		// out of one. Only together do they describe a file the site accepted
		// as data and is now being asked to execute.
		op: rx.MustNew(`/(uploads?|files?|media|attachments?|images?|img|avatars?|tmp|temp|user[-_]?content|wp-content/uploads)/` +
			`[^?#]*\.(php[345]?|phtml|asp[x]?|jsp[x]?|sh|py|pl|exe|cgi|htaccess)$`),
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Script execution from a user-content directory", category: CategoryInjection,
		tags: []string{TagFileupload, TagRce},
	},

	// -------------------------------------------------------------- reputation
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

	// --------------------------------------------------------------------- rce
	{
		id: 1100010, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform:    decoded,
		op:       rx.MustNew(`(os/exec|net/http/httputil|reflect\.ValueOf|unsafe\.Pointer|go\s+func\()`),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Potential Go code injection", category: CategoryRCE,
		tags: []string{TagRce, "golang"},
	},
	{
		id: 1100011, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform:    decoded,
		op:       rx.MustNew(`(runtime\.exec|java\.lang\.Runtime|java\.lang\.ProcessBuilder|javax\.crypto|javax\.script|ognl\.|java\.net\.URLClassLoader)`),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Potential Java code injection", category: CategoryRCE,
		tags: []string{TagRce, TagJava},
	},
	{
		// Node.js RCE and sandbox escape. Sits beside the Go and Java injection
		// rules and, like them, matches only unambiguous constructs — never a
		// bare "process.env", which is a plain property access that appears in
		// documentation and config text. Every alternative here is a specific
		// dangerous shape: require of a shell/fs module, an invoked
		// child_process/exec primitive, the .constructor.constructor("...")()
		// escape out of a template or vm sandbox, and the mainModule.require
		// pivot from a leaked process object. This coverage previously lived in
		// the Aho-Corasick fast path (now retired); moving it into the engine as
		// a grammar rule is both more accurate and, net of the fast path's
		// removal, cheaper per request.
		id: 1100016, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform:    decoded,
		op:       rx.MustNew(`(?i)(require\(\s*['"](child_process|fs)['"]\s*\)|child_process['"]?\s*\)?\s*\.\s*exec|\.constructor\.constructor\(|mainModule\.require|process\.mainModule|\bexecSync\(|\bspawnSync\()`),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Potential Node.js code injection", category: CategoryRCE,
		tags: []string{TagRce, "nodejs"},
	},
	{
		// Absolute paths to sensitive system files, in any request header.
		// gwaf's core rule 1003 already catches these in the URI and arguments;
		// this closes the header surface (Referer, X-Forwarded-For) the fast
		// path used to scan. The literals have no benign reading in a header, so
		// there is no false-positive cost to the added surface.
		id: 1100015, phase: types.PhaseRequestHeaders,
		targets: []types.Target{
			{Kind: types.TargetRequestHeaders}, {Kind: types.TargetRequestHeaderNames},
		},
		xform: norm,
		op: op.ContainsAny(
			"/etc/passwd", "/etc/shadow", "/proc/self/environ",
			"/windows/system32/config", ".ssh/id_rsa", ".aws/credentials",
		),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Access to sensitive system file via header", category: CategoryInjection,
		tags: []string{"lfi"},
	},
	{
		id: 1100014, phase: types.PhaseRequestHeaders,
		targets: []types.Target{
			{Kind: types.TargetRequestHeaders}, {Kind: types.TargetRequestHeaderNames},
			{Kind: types.TargetArgs}, {Kind: types.TargetArgNames},
		},
		xform:    decoded,
		op:       rx.MustNew(`\(\)\s*\{\s*[:;\s]*\}`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Shellshock attempt (CVE-2014-6271)", category: CategoryRCE,
		tags: []string{TagRce, "cve-2014-6271"},
	},
	{
		id: 1151000, phase: types.PhaseRequestBody, targets: tArgsHeadersURIBody,
		xform:    norm,
		op:       rx.MustNew(`\$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|nds|http):`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Log4Shell RCE attempt", category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2021-44228"},
	},
	{
		id: 1151001, phase: types.PhaseRequestBody, targets: tArgsNamesBody,
		xform:    decoded,
		op:       op.Contains("class.module.classLoader"),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Spring4Shell RCE attempt", category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2022-22965"},
	},
	{
		id: 1151002, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    norm,
		op:       rx.MustNew(`(?:;|\||&|\$|\n|\r)\s*(?:cat|ls|id|whoami|pwd|uname|netcat|nc|curl|wget|bash|sh|zsh|powershell|cmd\.exe)\b`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Medium, pl: 2,
		msg: "Generic command injection attempt", category: CategoryRCE,
		tags: []string{TagAttackRce},
	},
	{
		id: 1151003, phase: types.PhaseRequestBody, targets: tArgNames,
		xform:    decoded,
		op:       op.Contains("../"),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Path traversal in a parameter or file name (CVE-2023-50164)", category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2023-50164"},
	},
	{
		id: 1151004, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    decoded,
		op:       rx.MustNew(`(?:#|\$)\{.*\}`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Medium, pl: 2,
		msg: "Expression-language injection attempt (CVE-2022-22947)", category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2022-22947"},
	},
	{
		id: 1151005, phase: types.PhaseRequestHeaders, targets: tURI,
		xform:    norm,
		op:       op.Contains("/goanywhere/licensing/accept"),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Fortra GoAnywhere MFT RCE attempt (CVE-2023-0669)", category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2023-0669"},
	},
	{
		id: 1151006, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    norm,
		op:       rx.MustNew(`\$\{(?:script|dns|url):`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Text4Shell RCE attempt (CVE-2022-42889)", category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2022-42889"},
	},
	{
		id: 1151007, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    norm,
		op:       rx.MustNew(`ms-msdt:/id\s+it_browseforfile`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Follina RCE attempt (CVE-2022-30190)", category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2022-30190"},
	},
	{
		id: 1151008, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    norm,
		op:       rx.MustNew("(?:;|\\||&|\\$|\n|\r|`)\\s*(?:env|set|export|eval|exec|system|passthru|shell_exec|base64|python|perl|ruby|php|gcc|make|apt-get|yum|dnf)\\b"),
		status:   403,
		severity: types.SeverityCritical, conf: types.Medium, pl: 2,
		msg: "Advanced shell injection attempt", category: CategoryRCE,
		tags: []string{TagAttackRce},
	},
	// The body half of 1100014. That rule declares TargetArgs but runs at the
	// header phase, where gwaf never reads a body, so it only ever saw the query
	// string -- gwaf's own Diagnostics reported it as a rule that cannot detect
	// what it looks like it detects. A CGI host behind the gateway was
	// exploitable by POST while Shellshock read as covered.
	//
	// PL2, not PL1, and that is the whole cost of the fix. The pattern is all
	// metacharacters, so rx extracts no literal to prefilter on -- `\(\)` yields
	// "()", below rx's three-character floor -- which makes this rule
	// unconditional: it runs on every body in its phase. PL1 budgets four such
	// rules and already spends them, so putting this there would either break
	// TestUnconditionalRulesAreBudgeted or buy it off by raising the ceiling,
	// and a per-request regex is exactly what that ceiling exists to price.
	// Narrowing the pattern to earn a literal is worse than the gap: "(){" and
	// "() {" are extractable but "()  {" and "()\t{" are equally valid
	// Shellshock, so the rule would stop firing with nothing to say it had.
	// Query-string Shellshock is still caught at PL1 by 1100014; it is only the
	// body-borne form that now needs PL2.
	{
		id: 1151009, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    decoded,
		op:       rx.MustNew(`\(\)\s*\{\s*[:;\s]*\}`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 2,
		msg: "Shellshock attempt (CVE-2014-6271) (body)", category: CategoryRCE,
		tags: []string{TagAttackRce, "cve-2014-6271"},
	},

	// -------------------------------------------------------------------- sqli
	{
		id: 1140000, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform:    norm,
		op:       rx.MustNew(`(sleep\(|benchmark\(|pg_sleep\(|dbms_lock\.sleep\(|waitfor\s+delay)`),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Time-based blind SQL injection attempt", category: CategorySQLi,
		tags: []string{TagAttackSqli},
	},
	{
		id: 1140002, phase: types.PhaseRequestBody, targets: tArgs,
		xform:    norm,
		op:       rx.MustNew(`(information_schema\.|sys\.tables|sys\.objects|pg_catalog\.|mysql\.db|@@version)`),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "SQL schema enumeration attempt", category: CategorySQLi,
		tags: []string{TagAttackSqli},
	},
	{
		id: 1140001, phase: types.PhaseRequestBody, targets: tArgs,
		xform: norm,
		// The original also matched bare "--", "#" and "/*", which appear in
		// ordinary text often enough to be unusable at PL1. gwaf's structural
		// SQLi detector covers the comment-terminator bypass without the false
		// positives, so this keeps only the explicit tautology forms.
		op:       rx.MustNew(`'?\s+or\s+('?1'?\s*=\s*'?1|true)`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Medium, pl: 2,
		msg: "SQL injection authentication bypass attempt", category: CategorySQLi,
		tags: []string{TagAttackSqli},
	},
	{
		id: 1140003, phase: types.PhaseRequestHeaders, targets: header("X-siis-session-id"),
		op:       NewPresent("moveit-session-header"),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "MOVEit Transfer SQLi attempt (CVE-2023-34362)", category: CategorySQLi,
		tags: []string{TagAttackSqli, "cve-2023-34362"},
	},

	// --------------------------------------------------------------------- xss
	{
		id: 1141000, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform:    norm,
		op:       rx.MustNew(`(<script|on(load|error|click|mouseover|focus|submit|keydown|change)\s*=)`),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Cross-site scripting attempt", category: CategoryXSS,
		tags: []string{TagAttackXss},
	},
	{
		id: 1141002, phase: types.PhaseRequestBody, targets: tArgs,
		xform:    norm,
		op:       rx.MustNew(`(string\.fromcharcode|eval\(.*atob\(|eval\(.*base64|document\.write\(|unescape\()`),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Obfuscated cross-site scripting attempt", category: CategoryXSS,
		tags: []string{TagAttackXss},
	},
	{
		id: 1141001, phase: types.PhaseRequestBody, targets: tArgsHeadersURI,
		xform:    norm,
		op:       op.ContainsAny("<svg", "<iframe", "<object", "<embed", "<base", "<applet", "<meta"),
		status:   403,
		severity: types.SeverityError, conf: types.Medium, pl: 2,
		msg: "HTML tag injection", category: CategoryXSS,
		tags: []string{TagAttackXss},
	},

	// --------------------------------------------------------------- injection
	{
		id: 1160000, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform:    decoded,
		op:       rx.MustNew(`(\$where|\$gt|\$ne|\$lt|\$in|\$nin|\$exists|\$regex)`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Medium, pl: 2,
		msg: "NoSQL injection attempt", category: CategoryInjection,
		tags: []string{"attack-nosql"},
	},
	{
		id: 1170000, phase: types.PhaseRequestBody, targets: tArgsNamesBody,
		xform:    decoded,
		op:       op.ContainsAny("__proto__", "constructor.prototype"),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Prototype pollution attempt", category: CategoryExploit,
		tags: []string{TagAttackGeneric},
	},
	{
		id: 1170001, phase: types.PhaseRequestBody, targets: tArgsNamesBody,
		xform:    decoded,
		op:       op.ContainsAny("constructor[prototype]", ".prototype."),
		status:   403,
		severity: types.SeverityCritical, conf: types.Medium, pl: 2,
		msg: "Advanced prototype pollution attempt", category: CategoryExploit,
		tags: []string{TagAttackGeneric},
	},
	// Header phase only, and deliberately so. gwaf's Diagnostics flags this as a
	// rule that inspects arguments where the body is never read, and the obvious
	// "fix" -- a body-phase twin, as 1151009 is for Shellshock -- would match
	// every binary upload, because a PNG carries NULs in its first eight bytes.
	// A gateway that 403s image uploads is a worse outcome than a narrow rule.
	// TestNullByteStaysOutOfTheBodyPhase pins this decision.
	{
		id: 1150001, phase: types.PhaseRequestHeaders, targets: tArgsHeadersURI,
		xform:    decoded,
		op:       op.Contains("\x00"),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Null byte injection attempt", category: CategoryProtocol,
		tags: []string{TagAttackGeneric},
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
	{
		id: 1150003, phase: types.PhaseRequestBody, targets: tArgs,
		xform: norm,
		op: op.ContainsAny("127.0.0.1", "localhost", "169.254.169.254",
			"metadata.google.internal", "kubernetes.default.svc"),
		status:   403,
		severity: types.SeverityCritical, conf: types.Medium, pl: 2,
		msg: "SSRF attempt against an internal target", category: CategoryProtocol,
		tags: []string{"attack-ssrf"},
	},

	// ----------------------------------------------------------------- malware
	{
		id: 1100004, phase: types.PhaseRequestBody, targets: tFileNames,
		xform:    norm,
		op:       rx.MustNew(`\.(exe|php|phtml|sh|py|pl|rb|jsp|asp|aspx)$`),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Suspicious file upload extension", category: CategoryMalware,
		tags: []string{TagMalware, TagFileupload},
	},
	{
		id: 1100005, phase: types.PhaseRequestBody, targets: tArgs,
		xform:    norm,
		op:       op.Contains("<?php"),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "PHP code in a file upload", category: CategoryMalware,
		tags: []string{TagMalware, TagRce},
	},
	{
		id: 1100006, phase: types.PhaseRequestBody, targets: tArgs,
		op:       rx.MustNew(`%PDF-1\.[0-7].*obj.*<<.*/JS.*>>.*endobj`),
		status:   403,
		severity: types.SeverityError, conf: types.High, pl: 1,
		msg: "PDF containing JavaScript", category: CategoryMalware,
		tags: []string{TagMalware, TagFileupload},
	},
	{
		id: 1100007, phase: types.PhaseRequestBody, targets: tFileNames,
		xform: norm,
		op: rx.MustNew(
			`\.(locky|crypt|wncry|cryptolocker|zepto|aesir|thor|lockbit|clop|conti|ryuk|cerber|gandcrab|pysa)$`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Ransomware file extension", category: CategoryRansomware,
		tags: []string{TagRansomware},
	},
	{
		id: 1100008, phase: types.PhaseRequestHeaders, targets: tPath,
		xform:    norm,
		op:       rx.MustNew(`/(c99|r57|sh3ll|weevely|pas|cmd|shell|backdoor|tunnel|proxy)\.(php|asp|aspx|jsp|pl|py|sh|cgi)`),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Web shell filename requested", category: CategoryMalware,
		tags: []string{TagMalware, TagRce},
	},
	{
		id: 1100009, phase: types.PhaseRequestHeaders, targets: tPath,
		xform:    norm,
		op:       rx.MustNew(`(read_me|decrypt_files|your_files_are_encrypted|recover_files|readme_for_decrypt)\.(txt|html|htm|png)`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Ransomware note filename requested", category: CategoryRansomware,
		tags: []string{TagRansomware},
	},
	{
		id: 1142000, phase: types.PhaseRequestBody, targets: tArgs,
		xform: norm,
		// Deliberately PL3. The original blocked any upload containing "key",
		// "lock" or "payment", which is ordinary vocabulary for a payments or
		// key-management API. It is kept for operators who want it, not run by
		// default.
		op:       op.ContainsAny("ransom", "bitcoin", ".onion", "cryptolocker"),
		status:   403,
		severity: types.SeverityWarning, conf: types.Low, pl: 3,
		msg: "Ransomware keywords in a file upload", category: CategoryRansomware,
		tags: []string{TagRansomware},
	},
	{
		id: 1190000, phase: types.PhaseRequestBody, targets: tArgsBody,
		xform: norm,
		op: op.ContainsAny("coinhive.min.js", "authedmine.min.js", "cryptonight.wasm",
			"monerominer", "miner.start"),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Cryptocurrency miner script detected", category: CategoryExploit,
		tags: []string{"attack-malware"},
	},

	// --------------------------------------------------------------- wordpress
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
		id: 1100003, phase: types.PhaseRequestHeaders, targets: tPath,
		xform:    norm,
		op:       rx.MustNew(`/wp-content/plugins/.*\.php`),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "WordPress plugin execution attempt", category: CategoryWordPress,
		tags: []string{TagWpScan},
	},
	{
		id: 1100012, phase: types.PhaseRequestHeaders, targets: tPath,
		xform:    norm,
		op:       rx.MustNew(`(wp-json/wp/v2/users|wp-links-opml\.php|wp-config-sample\.php|wp-content/debug\.log|readme\.html|license\.txt|wp-content/uploads/.*\.php)`),
		status:   403,
		severity: types.SeverityError, conf: types.High, pl: 1,
		msg: "WordPress enumeration or information leak attempt", category: CategoryWordPress,
		tags: []string{TagWpScan},
	},

	// ----------------------------------------------------------------- scanner
	{
		id: 1110000, phase: types.PhaseRequestHeaders, targets: header("User-Agent"),
		xform: norm,
		op: op.ContainsAny("nikto", "sqlmap", "acunetix", "nessus", "openvas", "arachni",
			"w3af", "dirbuster", "gobuster", "rustscan", "masscan", "zgrab",
			"nmap", "netsparker", "qualys", "censys", "shodan"),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Vulnerability scanner user agent", category: CategoryScanner,
		tags: []string{TagScanner, "recon"},
	},
	{
		id: 1110001, phase: types.PhaseRequestHeaders, targets: tHeaderNames,
		xform: norm,
		op: op.ContainsAny("x-scanner", "acunetix-product", "acunetix-scanning-agreement",
			"nessus-check", "qualys-scan-as", "netsparker-scan-id"),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Vulnerability scanner header", category: CategoryScanner,
		tags: []string{TagScanner},
	},
	{
		id: 1110002, phase: types.PhaseRequestHeaders, targets: tPath,
		xform:    norm,
		op:       rx.MustNew(`\b(shell|cmd|sh|bash|zsh|powershell|nc|netcat|web-shell|backdoor)\.(php|asp|aspx|jsp|sh|py|pl)\b`),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Search for a common web shell or backdoor", category: CategoryScanner,
		tags: []string{TagScanner, TagRce},
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
		id: 1110004, phase: types.PhaseRequestHeaders, targets: tPath,
		xform: norm,
		op: op.ContainsAny("/.env", "/.git", "/.vscode", "/.idea",
			"/docker-compose.yml", "/config.php.bak"),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Sensitive file discovery attempt", category: CategoryScanner,
		tags: []string{TagScanner, "recon"},
	},

	// ------------------------------------------------------------------ origin
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

	// --------------------------------------------------------------------- dlp
	// Response-phase rules. They are only reachable when response inspection is
	// enabled, which is an enterprise-tier setting: see policy.go.
	{
		id: 1130000, phase: types.PhaseResponseBody, targets: tRespBody,
		// Issuer prefix, permitted length and Luhn together, rather than the
		// Visa-shaped regex this replaces: that one missed every other brand and
		// blocked on any sixteen digits starting with a 4. See CardNumber.
		op:     NewCardNumber(),
		status: 403,
		// High rather than Medium, and PL1 rather than PL2: response inspection
		// is already opt-in and enterprise-tier, so gating these behind the
		// paranoia level as well means an operator turns DLP on and nothing
		// happens. The opt-in is the gate.
		//
		// Certain rather than High now that the check digit has to agree: a
		// sixteen-digit string that carries an assigned prefix and validates
		// under Luhn is a card number, not a number that resembles one.
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Card number in response", category: CategoryDLP,
		tags: []string{TagDlp, "compliance"},
	},
	{
		id: 1130001, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`\b\d{3}-\d{2}-\d{4}\b`),
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "US social security number in response", category: CategoryDLP,
		tags: []string{TagDlp, "compliance"},
	},
	{
		id: 1130002, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opPrivateKeyPEM,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Private key in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130003, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opAWSAccessKey,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "AWS access key in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130004, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opGoogleAPIKey,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Google API key in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130005, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opSlackWebhook,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Slack webhook URL in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130006, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opGitHubPAT,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "GitHub personal access token in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130007, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opGoogleOAuth,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Google OAuth client secret in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},

	// The detectors above cover six credential shapes. The ones below are the
	// rest of what actually ends up in a response body: a payment processor's
	// live key, a git forge token, a model provider's key, a mail or telephony
	// key, a package registry token, a cloud service account, and a database URI
	// with the password still in it. Each is recognised by an issuer-assigned
	// prefix rather than by entropy, so a match is the credential and not a
	// string that resembles one — which is why they sit at PL1 alongside the
	// originals.
	{
		id: 1130008, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opStripeLiveKey,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Stripe live API key in response", category: CategoryDLP,
		tags: []string{TagDlp, "compliance"},
	},
	{
		// ghp_ has its own rule above; this covers the OAuth, user-to-server,
		// server-to-server and refresh prefixes, which leak from the same places
		// and were simply never listed.
		id: 1130009, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opGitHubToken,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "GitHub token in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130010, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opGitHubFinePAT,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "GitHub fine-grained personal access token in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		// T3BlbkFJ is "OpenAI" in base64 and sits in the middle of every key the
		// provider issues, which is what makes this specific rather than a match
		// on any sk- prefixed string.
		id: 1130011, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opOpenAIKey,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "OpenAI API key in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130012, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opAnthropicKey,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Anthropic API key in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130013, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opSlackToken,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Slack token in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130014, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opSendGridKey,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "SendGrid API key in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		// Account SID and API key SID share a shape: two fixed letters and 32
		// hex. That is the weakest signal of any credential rule here — a hex
		// digest preceded by those letters matches, and the alternation leaves
		// the prefilter no literal to skip on, so the rule runs over every
		// inspected response body. PL2 and Medium for both reasons: it is the
		// one detector in this group whose false positive is plausible, and PL1
		// has a standing budget for rules the prefilter cannot skip
		// (TestUnconditionalRulesAreBudgeted) that this would spend.
		id: 1130015, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`\b(?:AC|SK)[0-9a-f]{32}\b`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Medium, pl: 2,
		msg: "Twilio account or API key SID in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130016, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opNPMToken,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "npm access token in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130017, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opPyPIToken,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "PyPI upload token in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		// The private key inside a service-account file is caught by 1130002;
		// this catches the file itself, including the copies that have had the
		// key stripped but still carry the client id and project.
		id: 1130018, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opGCPServiceAcct,
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Google Cloud service account key in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130019, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opAzureStorageKey,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Azure storage account key in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		// A connection string with the password still in it is the leak that
		// costs the most and looks the most ordinary — it arrives in a config
		// dump, a health endpoint or an error page, and reads as a URL.
		id: 1130020, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opDBURICreds,
		status:   403,
		severity: types.SeverityCritical, conf: types.High, pl: 1,
		msg: "Database connection string with credentials in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		// The PEM rule above covers OPENSSH and every other "BEGIN ... PRIVATE
		// KEY" banner. PuTTY's format does not use one.
		id: 1130021, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       opPuTTYKey,
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "PuTTY private key in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},

	// Structural disclosure: a stack trace or a database error page. These leak
	// far more often than a card number does and are what the CRS RESPONSE-950
	// family covers — file paths, framework versions, query fragments and the
	// shape of the schema, all of which are reconnaissance for the next request.
	//
	// PL2 and Medium, unlike the credential rules above, because the false
	// positive is real and specific: a site whose job is to display stack traces
	// — an error tracker, a CI dashboard, a paste service, documentation — is
	// serving them legitimately. Enterprise tier raises the paranoia level to 2
	// and gets these; a standard-tier install that opts into DLP alone stays at
	// PL1 and gets the credential rules only.
	{
		id: 1130022, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`goroutine \d+ \[[a-z ]+\]:`),
		status:   403,
		severity: types.SeverityError, conf: types.Medium, pl: 2,
		msg: "Go panic stack trace in response", category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage},
	},
	{
		id: 1130023, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       op.Contains("Traceback (most recent call last):"),
		status:   403,
		severity: types.SeverityError, conf: types.Medium, pl: 2,
		msg: "Python traceback in response", category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage},
	},
	{
		id: 1130024, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`\bat [a-zA-Z_$][\w$]*(?:\.[\w$]+)+\([\w$]+\.java:\d+\)`),
		status:   403,
		severity: types.SeverityError, conf: types.Medium, pl: 2,
		msg: "Java stack trace in response", category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage},
	},
	{
		id: 1130025, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`(?:Fatal error|Parse error|Warning|Notice):[^\n]{0,200}? in [^\n]{0,200}? on line \d+`),
		status:   403,
		severity: types.SeverityError, conf: types.Medium, pl: 2,
		msg: "PHP error with source path in response", category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage, TagPhp},
	},
	{
		id: 1130026, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`\bSystem\.[A-Za-z0-9.]+Exception\b[^\n]{0,200}?\bat [A-Za-z0-9_.<>]+\(`),
		status:   403,
		severity: types.SeverityError, conf: types.Medium, pl: 2,
		msg: ".NET exception trace in response", category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage},
	},
	{
		id: 1130027, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`\.rb:\d+:in `),
		status:   403,
		severity: types.SeverityError, conf: types.Medium, pl: 2,
		msg: "Ruby backtrace in response", category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage},
	},
	{
		// Literals rather than a pattern: each of these is a database engine
		// naming itself in an error it should never have shown a client, and a
		// literal set gives the compiler something to prefilter on.
		id: 1130028, phase: types.PhaseResponseBody, targets: tRespBody,
		op: op.ContainsAny(
			"You have an error in your SQL syntax",
			"Unclosed quotation mark after the character string",
			"SQLSTATE[",
			"SQLiteException",
			"psycopg2.",
			"Npgsql.",
			"org.postgresql.util.PSQLException",
			"com.mysql.jdbc.exceptions",
			"Microsoft OLE DB Provider for SQL Server",
			"Warning: mysql_",
			"supplied argument is not a valid MySQL",
		),
		status:   403,
		severity: types.SeverityError, conf: types.Medium, pl: 2,
		msg: "Database engine error text in response", category: CategoryDLP,
		tags: []string{TagDlp, TagLeakage},
	},

	// ------------------------------------------------------------ dlp-inbound
	// The same credential detectors, pointed the other way.
	//
	// Data-leak control has so far meant "do not let the origin leak outward",
	// which is half of it. The other half is a secret arriving: an engineer
	// pasting an AWS key into a support ticket, a private key attached to an
	// issue, a connection string typed into a chat app — all of them behind this
	// gateway, all of them landing in a database and a backup and a search
	// index, and none of them visible to anything gateon previously ran.
	//
	// Two deliberate differences from the response-phase rules above.
	//
	// They log rather than block. Refusing a POST because it contains a secret
	// throws away what the user typed and teaches them to route around the
	// gateway, which is a worse outcome than the leak: now nobody can see it at
	// all. Redaction is worse still — silently altering what someone wrote is
	// not a security control, it is data loss. So these record, and the finding
	// reaches the Security Hub through the same path every other match does.
	//
	// And they carry no card or SSN detector. Outbound, a card number is a leak;
	// inbound, it is a customer paying for something, and a checkout form is the
	// single most expensive place a WAF can be wrong. The asymmetry is the whole
	// reason these are separate rules rather than the same rules with two
	// phases.
	//
	// PL2, which is where enterprise tier sits: the detectors are Certain, but
	// scanning every request body is a cost a minimal deployment should not pay
	// silently.
	{
		id: 1131000, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opPrivateKeyPEM,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "Private key sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131001, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opAWSAccessKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "AWS access key sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131002, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opStripeLiveKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "Stripe live API key sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131003, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opGitHubPAT,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "GitHub personal access token sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131004, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opGitHubToken,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "GitHub token sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131005, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opGitHubFinePAT,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "GitHub fine-grained personal access token sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131006, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opOpenAIKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "OpenAI API key sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131007, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opAnthropicKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "Anthropic API key sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131008, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opSlackToken,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "Slack token sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131009, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opSlackWebhook,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "Slack webhook URL sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131010, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opGoogleAPIKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "Google API key sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131011, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opGoogleOAuth,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "Google OAuth client secret sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131012, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opGCPServiceAcct,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "Google Cloud service account key sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131013, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opAzureStorageKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "Azure storage account key sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131014, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opSendGridKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "SendGrid API key sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131015, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opNPMToken,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "npm access token sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131016, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opPyPIToken,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "PyPI upload token sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131017, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opPuTTYKey,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "PuTTY private key sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
	{
		id: 1131018, phase: types.PhaseRequestBody, targets: tArgsBody,
		op:       opDBURICreds,
		action:   rules.Log,
		severity: types.SeverityWarning, conf: types.Certain, pl: 2,
		msg: "Database connection string with credentials sent in a request", category: CategoryDLP,
		tags: []string{TagDlp, TagDlpInbound},
	},
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
