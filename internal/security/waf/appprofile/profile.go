// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package appprofile

import (
	"sort"
	"strings"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/profiles"
)

// Profile names a platform whose ordinary traffic is a superset of an attack
// shape, and which therefore needs a handful of scoped exceptions to run behind
// the default ruleset without blocking itself.
//
// This is not a "compatibility mode" and it does not turn rules off. Every entry
// gwaf ships names a rule, a path, a target and a field, and carries a rationale
// — a WordPress comment field really does contain "<?php echo $name; ?>", and a
// Jira issue really does quote "1' OR '1'='1". They are benign because of where
// they land: a field that is stored and displayed, never executed. Where a value
// lands is knowledge the deployment has and the engine does not, which is why
// this is configuration rather than detection.
//
// Weakening the underlying rules instead was measured and rejected upstream:
// demoting the PHP open-tag signal removed the false positive and also dropped
// 32 real exploits, taking RCE detection from 84% to 43%.
type Profile string

// The profiles gwaf ships. They compose — an install running WordPress behind a
// Laravel API can enable both, because every exception is scoped by path and a
// path belongs to one application.
const (
	WordPress    Profile = "wordpress"
	Drupal       Profile = "drupal"
	Laravel      Profile = "laravel"
	IssueTracker Profile = "issue_tracker"
)

// byName maps a configured name onto the exception set it selects.
//
// The functions are called per lookup rather than cached: an engine is built
// once per distinct config fingerprint, not per request, and holding a package
// level slice would let a caller that appends to the result corrupt every
// subsequent build.
var byName = map[Profile]func() []rules.Exception{
	WordPress:    profiles.WordPress,
	Drupal:       profiles.Drupal,
	Laravel:      profiles.Laravel,
	IssueTracker: profiles.IssueTracker,
}

// Names lists the profiles this build understands, sorted so the API
// and the dashboard render them in a stable order.
func Names() []string {
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, string(name))
	}
	sort.Strings(names)
	return names
}

// Parse normalises a configured name.
//
// Case and separator are forgiven — "WordPress", "issue-tracker" and
// "issue_tracker" all resolve — because these names are typed into a dashboard
// field and a config file, and rejecting "WordPress" for its capital letters
// would be a support ticket rather than a safety property.
func Parse(s string) (Profile, bool) {
	normalised := strings.ToLower(strings.TrimSpace(s))
	normalised = strings.ReplaceAll(normalised, "-", "_")
	normalised = strings.ReplaceAll(normalised, " ", "_")
	// The compact spellings people actually write.
	switch normalised {
	case "issuetracker", "jira", "gitlab":
		normalised = string(IssueTracker)
	case "wp":
		normalised = string(WordPress)
	}
	p := Profile(normalised)
	if _, ok := byName[p]; !ok {
		return "", false
	}
	return p, true
}

// Exceptions resolves configured profile names to their exceptions.
//
// Unknown names are returned rather than dropped. A profile that silently did
// nothing is the worst outcome available here: the operator reads the dashboard,
// sees the platform they selected, and concludes their false positives are
// somebody else's problem — while the exceptions that would have fixed them were
// never loaded. The caller logs what it could not resolve.
func Exceptions(names []string) (exceptions []rules.Exception, unknown []string) {
	seen := make(map[Profile]bool, len(names))
	for _, raw := range names {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		p, ok := Parse(raw)
		if !ok {
			unknown = append(unknown, raw)
			continue
		}
		// Enabling a profile twice must not double its exceptions: they are
		// matched, not counted, so duplicates are only wasted work per request.
		if seen[p] {
			continue
		}
		seen[p] = true
		exceptions = append(exceptions, byName[p]()...)
		// gwaf answers "is this field displayed rather than executed" for the
		// rules it ships and cannot answer it for the ones gateon adds, because
		// it has never heard of them. Without this a paste service selecting a
		// profile had gwaf's exceptions applied and gateon's own rules still
		// refusing the same content.
		exceptions = append(exceptions, GateonExceptions(p)...)
	}
	return exceptions, unknown
}

// Normalise returns the canonical spelling of the profiles it
// recognises, dropping duplicates and unknown names and preserving the caller's
// order. It is what the API returns and what the dashboard displays.
func Normalise(names []string) []string {
	out := make([]string, 0, len(names))
	seen := make(map[Profile]bool, len(names))
	for _, raw := range names {
		p, ok := Parse(raw)
		if !ok || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, string(p))
	}
	return out
}

// Fingerprint renders a profile list for the config fingerprint.
//
// It resolves known names to their canonical form so "WordPress" and
// "wordpress" hash alike and build one engine rather than two identical ones.
// It also carries the *unknown* names through, sorted, which is the part worth
// explaining: a misspelled profile produces the same ruleset as no profile at
// all, so collapsing the two would be correct for caching and wrong for
// operations — the engine that logs "unknown WAF app profile" is only built
// once per fingerprint, and the operator with the typo would never see it.
// Keeping the typo in the key costs one extra engine on a misconfigured install
// and guarantees the warning reaches whoever made the mistake.
func Fingerprint(names []string) string {
	known := Normalise(names)
	_, unknown := Exceptions(names)
	sort.Strings(unknown)
	return strings.Join(known, ",") + "|" + strings.Join(unknown, ",")
}
