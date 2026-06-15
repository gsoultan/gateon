// Package yara implements a dependency-free, pure-Go signature engine
// ("YARA-lite") for inspecting uploaded file content for known malware,
// webshells, exploit payloads, and other malicious indicators.
//
// It is intentionally not a full YARA implementation (no external libyara/cgo
// dependency): a Rule is a set of byte/text Strings combined with a simple
// MatchAny/MatchAll condition. This keeps detection fast and in-memory so it
// can run inline on the request path, while still covering the common
// "detect vulnerable/malicious files" use cases (à la Wazuh).
//
// All exported types are safe for concurrent use after the Engine is built:
// rules are compiled once and never mutated, and Scan only reads.
package yara

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Severity classifies how dangerous a rule match is. Consumers typically block
// on High/Critical and log Low/Medium.
type Severity string

const (
	// SeverityLow marks informational/suspicious indicators.
	SeverityLow Severity = "low"
	// SeverityMedium marks indicators that warrant attention.
	SeverityMedium Severity = "medium"
	// SeverityHigh marks strong indicators of malicious content.
	SeverityHigh Severity = "high"
	// SeverityCritical marks unambiguous malware/exploit signatures.
	SeverityCritical Severity = "critical"
)

// rank orders severities so a threshold comparison is possible.
func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool {
	return s.rank() >= min.rank()
}

// MatchMode controls how a rule's Strings combine into a match.
type MatchMode string

const (
	// MatchAny (default) matches when any one of the rule's Strings is present.
	MatchAny MatchMode = "any"
	// MatchAll matches only when every one of the rule's Strings is present.
	MatchAll MatchMode = "all"
)

// Pattern is a single byte/text signature within a Rule. Exactly one of Text
// or Hex must be set. Hex is a sequence of hex pairs (e.g. "7f454c46") used for
// binary magic bytes; Text is a literal string.
type Pattern struct {
	Text            string `json:"text,omitzero"`
	Hex             string `json:"hex,omitzero"`
	CaseInsensitive bool   `json:"case_insensitive,omitzero"`
}

// Rule is a named detection signature: a set of Strings combined per Mode.
type Rule struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitzero"`
	Severity    Severity `json:"severity,omitzero"`
	Tags        []string `json:"tags,omitzero"`
	// MITRE holds ATT&CK technique IDs associated with the rule (e.g. "T1059").
	MITRE   []string  `json:"mitre,omitzero"`
	Strings []Pattern `json:"strings"`
	Mode    MatchMode `json:"mode,omitzero"`
}

// compiledPattern is a Pattern with its needle resolved to raw bytes once.
type compiledPattern struct {
	needle          []byte
	caseInsensitive bool
	label           string // human-readable description for match reporting
}

// compiledRule is a Rule with all patterns compiled and the mode normalized.
type compiledRule struct {
	rule     Rule
	patterns []compiledPattern
	all      bool
}

// compile resolves a Pattern to its raw needle bytes, rejecting empty/invalid
// patterns so a misconfigured rule fails fast at build time rather than
// silently never matching.
func (p Pattern) compile() (compiledPattern, error) {
	switch {
	case p.Hex != "":
		raw, err := hex.DecodeString(strings.ReplaceAll(p.Hex, " ", ""))
		if err != nil {
			return compiledPattern{}, fmt.Errorf("invalid hex pattern %q: %w", p.Hex, err)
		}
		if len(raw) == 0 {
			return compiledPattern{}, fmt.Errorf("empty hex pattern")
		}
		return compiledPattern{needle: raw, label: "hex:" + p.Hex}, nil
	case p.Text != "":
		return compiledPattern{
			needle:          []byte(p.Text),
			caseInsensitive: p.CaseInsensitive,
			label:           p.Text,
		}, nil
	default:
		return compiledPattern{}, fmt.Errorf("pattern has neither text nor hex")
	}
}
