// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

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
}

// rule renders the spec as a gwaf rule.
func (s spec) rule() rules.Rule {
	action := rules.Block
	if s.status != 0 {
		action = rules.BlockWithStatus(s.status)
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
		op:     rx.MustNew(`\b4[0-9]{12}(?:[0-9]{3})?\b`),
		status: 403,
		// High rather than Medium, and PL1 rather than PL2: response inspection
		// is already opt-in and enterprise-tier, so gating these behind the
		// paranoia level as well means an operator turns DLP on and nothing
		// happens. The opt-in is the gate.
		severity: types.SeverityCritical, conf: types.High, pl: 1,
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
		op:       rx.MustNew(`-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Private key in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130003, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`\bAKIA[0-9A-Z]{16}\b`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "AWS access key in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130004, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`AIza[0-9A-Za-z\-_]{35}`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Google API key in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130005, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       op.Contains("https://hooks.slack.com/services/"),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Slack webhook URL in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130006, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`ghp_[a-zA-Z0-9]{36}`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "GitHub personal access token in response", category: CategoryDLP,
		tags: []string{TagDlp},
	},
	{
		id: 1130007, phase: types.PhaseResponseBody, targets: tRespBody,
		op:       rx.MustNew(`GOCSPX-[a-zA-Z0-9\-_]{28}`),
		status:   403,
		severity: types.SeverityCritical, conf: types.Certain, pl: 1,
		msg: "Google OAuth client secret in response", category: CategoryDLP,
		tags: []string{TagDlp},
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
