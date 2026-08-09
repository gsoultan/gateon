// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package waf

import (
	"sort"
	"strings"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/profiles"
)

// AppProfile names a platform whose ordinary traffic is a superset of an attack
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
type AppProfile string

// The profiles gwaf ships. They compose — an install running WordPress behind a
// Laravel API can enable both, because every exception is scoped by path and a
// path belongs to one application.
const (
	AppProfileWordPress    AppProfile = "wordpress"
	AppProfileDrupal       AppProfile = "drupal"
	AppProfileLaravel      AppProfile = "laravel"
	AppProfileIssueTracker AppProfile = "issue_tracker"
)

// appProfiles maps a configured name onto the exception set it selects.
//
// The functions are called per lookup rather than cached: an engine is built
// once per distinct config fingerprint, not per request, and holding a package
// level slice would let a caller that appends to the result corrupt every
// subsequent build.
var appProfiles = map[AppProfile]func() []rules.Exception{
	AppProfileWordPress:    profiles.WordPress,
	AppProfileDrupal:       profiles.Drupal,
	AppProfileLaravel:      profiles.Laravel,
	AppProfileIssueTracker: profiles.IssueTracker,
}

// AppProfileNames lists the profiles this build understands, sorted so the API
// and the dashboard render them in a stable order.
func AppProfileNames() []string {
	names := make([]string, 0, len(appProfiles))
	for name := range appProfiles {
		names = append(names, string(name))
	}
	sort.Strings(names)
	return names
}

// ParseAppProfile normalises a configured name.
//
// Case and separator are forgiven — "WordPress", "issue-tracker" and
// "issue_tracker" all resolve — because these names are typed into a dashboard
// field and a config file, and rejecting "WordPress" for its capital letters
// would be a support ticket rather than a safety property.
func ParseAppProfile(s string) (AppProfile, bool) {
	normalised := strings.ToLower(strings.TrimSpace(s))
	normalised = strings.ReplaceAll(normalised, "-", "_")
	normalised = strings.ReplaceAll(normalised, " ", "_")
	// The compact spellings people actually write.
	switch normalised {
	case "issuetracker", "jira", "gitlab":
		normalised = string(AppProfileIssueTracker)
	case "wp":
		normalised = string(AppProfileWordPress)
	}
	p := AppProfile(normalised)
	if _, ok := appProfiles[p]; !ok {
		return "", false
	}
	return p, true
}

// AppProfileExceptions resolves configured profile names to their exceptions.
//
// Unknown names are returned rather than dropped. A profile that silently did
// nothing is the worst outcome available here: the operator reads the dashboard,
// sees the platform they selected, and concludes their false positives are
// somebody else's problem — while the exceptions that would have fixed them were
// never loaded. The caller logs what it could not resolve.
func AppProfileExceptions(names []string) (exceptions []rules.Exception, unknown []string) {
	seen := make(map[AppProfile]bool, len(names))
	for _, raw := range names {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		p, ok := ParseAppProfile(raw)
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
		exceptions = append(exceptions, appProfiles[p]()...)
	}
	return exceptions, unknown
}

// NormaliseAppProfiles returns the canonical spelling of the profiles it
// recognises, dropping duplicates and unknown names and preserving the caller's
// order. It is what the API returns and what the dashboard displays.
func NormaliseAppProfiles(names []string) []string {
	out := make([]string, 0, len(names))
	seen := make(map[AppProfile]bool, len(names))
	for _, raw := range names {
		p, ok := ParseAppProfile(raw)
		if !ok || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, string(p))
	}
	return out
}

// AppProfileFingerprint renders a profile list for the config fingerprint.
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
func AppProfileFingerprint(names []string) string {
	known := NormaliseAppProfiles(names)
	_, unknown := AppProfileExceptions(names)
	sort.Strings(unknown)
	return strings.Join(known, ",") + "|" + strings.Join(unknown, ",")
}
