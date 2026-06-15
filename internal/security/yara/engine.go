package yara

import (
	"bytes"
	"fmt"
)

// Match is the result of a Rule matching scanned content.
type Match struct {
	Rule           string   `json:"rule"`
	Description    string   `json:"description,omitzero"`
	Severity       Severity `json:"severity"`
	Tags           []string `json:"tags,omitzero"`
	MITRE          []string `json:"mitre,omitzero"`
	MatchedStrings []string `json:"matched_strings,omitzero"`
}

// Engine holds a compiled, immutable set of rules. It is safe for concurrent
// use by multiple goroutines once created with New or Default.
type Engine struct {
	rules []compiledRule
}

// New compiles rules into an Engine. It returns an error if any rule is
// malformed (empty name, no strings, or an invalid pattern) so misconfiguration
// is caught at startup rather than silently disabling detection.
func New(rules []Rule) (*Engine, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		cr, err := compileRule(r)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, cr)
	}
	return &Engine{rules: compiled}, nil
}

// Default returns an Engine preloaded with the built-in malware/exploit
// ruleset. The built-in rules are validated at package init, so Default never
// fails.
func Default() *Engine {
	return defaultEngine
}

// compileRule validates and compiles a single rule.
func compileRule(r Rule) (compiledRule, error) {
	if r.Name == "" {
		return compiledRule{}, fmt.Errorf("yara: rule has empty name")
	}
	if len(r.Strings) == 0 {
		return compiledRule{}, fmt.Errorf("yara: rule %q has no strings", r.Name)
	}
	if r.Severity == "" {
		r.Severity = SeverityMedium
	}
	pats := make([]compiledPattern, 0, len(r.Strings))
	for _, p := range r.Strings {
		cp, err := p.compile()
		if err != nil {
			return compiledRule{}, fmt.Errorf("yara: rule %q: %w", r.Name, err)
		}
		pats = append(pats, cp)
	}
	return compiledRule{rule: r, patterns: pats, all: r.Mode == MatchAll}, nil
}

// RuleCount returns the number of compiled rules.
func (e *Engine) RuleCount() int {
	if e == nil {
		return 0
	}
	return len(e.rules)
}

// Scan inspects data against every rule and returns all matches. An empty
// result means the content is clean with respect to the loaded rules. Scanning
// is read-only and allocation-light (no copy of data).
func (e *Engine) Scan(data []byte) []Match {
	if e == nil || len(data) == 0 {
		return nil
	}
	var matches []Match
	for i := range e.rules {
		if m, ok := e.rules[i].evaluate(data); ok {
			matches = append(matches, m)
		}
	}
	return matches
}

// HighestSeverity returns the most severe match in the set (or empty string for
// no matches), letting callers make a single block/allow decision.
func HighestSeverity(matches []Match) Severity {
	var top Severity
	for _, m := range matches {
		if m.Severity.rank() > top.rank() {
			top = m.Severity
		}
	}
	return top
}

// evaluate applies a single compiled rule to data.
func (r compiledRule) evaluate(data []byte) (Match, bool) {
	hit := make([]string, 0, len(r.patterns))
	for _, p := range r.patterns {
		if indexOf(data, p) >= 0 {
			hit = append(hit, p.label)
		} else if r.all {
			// MatchAll: a single missing pattern disqualifies the rule.
			return Match{}, false
		}
	}
	if len(hit) == 0 {
		return Match{}, false
	}
	return Match{
		Rule:           r.rule.Name,
		Description:    r.rule.Description,
		Severity:       r.rule.Severity,
		Tags:           r.rule.Tags,
		MITRE:          r.rule.MITRE,
		MatchedStrings: hit,
	}, true
}

// indexOf returns the index of the pattern's needle in data, honouring
// case-insensitivity without allocating a lowercased copy of data.
func indexOf(data []byte, p compiledPattern) int {
	if !p.caseInsensitive {
		return bytes.Index(data, p.needle)
	}
	return indexFold(data, p.needle)
}

// indexFold finds needle in data using ASCII case-insensitive comparison.
// It allocates nothing and runs in O(len(data)*len(needle)); needles are short
// signatures and data is bounded by the caller, so this is acceptable inline.
func indexFold(data, needle []byte) int {
	n := len(needle)
	if n == 0 {
		return 0
	}
	if n > len(data) {
		return -1
	}
	first := lowerASCII(needle[0])
	for i := 0; i <= len(data)-n; i++ {
		if lowerASCII(data[i]) != first {
			continue
		}
		if equalFold(data[i:i+n], needle) {
			return i
		}
	}
	return -1
}

// equalFold compares two equal-length byte slices for ASCII case-insensitive
// equality.
func equalFold(a, b []byte) bool {
	for i := range a {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

// lowerASCII lowercases a single ASCII byte, leaving non-letters untouched.
func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
