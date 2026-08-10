// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf_test

import (
	"slices"
	"strings"
	"testing"

	secwaf "github.com/gsoultan/gateon/internal/security/waf"
)

// TestParseAppProfileAcceptsTheSpellingsPeopleWrite covers the normalisation
// that keeps a dashboard field from becoming a support ticket. These names are
// typed by hand into a config file and a text input, so "WordPress" and
// "issue-tracker" have to resolve.
func TestParseAppProfileAcceptsTheSpellingsPeopleWrite(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in   string
		want secwaf.AppProfile
	}{
		{"wordpress", secwaf.AppProfileWordPress},
		{"WordPress", secwaf.AppProfileWordPress},
		{"  WORDPRESS  ", secwaf.AppProfileWordPress},
		{"wp", secwaf.AppProfileWordPress},
		{"issue_tracker", secwaf.AppProfileIssueTracker},
		{"issue-tracker", secwaf.AppProfileIssueTracker},
		{"issuetracker", secwaf.AppProfileIssueTracker},
		{"jira", secwaf.AppProfileIssueTracker},
		{"gitlab", secwaf.AppProfileIssueTracker},
		{"drupal", secwaf.AppProfileDrupal},
		{"laravel", secwaf.AppProfileLaravel},
	} {
		got, ok := secwaf.ParseAppProfile(tc.in)
		if !ok || got != tc.want {
			t.Errorf("ParseAppProfile(%q) = %q, %v; want %q, true", tc.in, got, ok, tc.want)
		}
	}

	for _, bad := range []string{"", "   ", "wordpres", "magento", "../../etc/passwd"} {
		if got, ok := secwaf.ParseAppProfile(bad); ok {
			t.Errorf("ParseAppProfile(%q) = %q, true; want not recognised", bad, got)
		}
	}
}

// TestAppProfileExceptionsReportsUnknownNames is the operational half of the
// feature. A profile that silently does nothing is the worst outcome available:
// the operator selects their platform, believes the tuning is loaded, and
// concludes the false positives are somebody else's problem.
func TestAppProfileExceptionsReportsUnknownNames(t *testing.T) {
	t.Parallel()

	ex, unknown := secwaf.AppProfileExceptions([]string{"wordpress", "magento", ""})

	if len(ex) == 0 {
		t.Error("wordpress profile contributed no exceptions")
	}
	if !slices.Equal(unknown, []string{"magento"}) {
		t.Errorf("unknown = %v; want [magento] — an empty entry is not an error, a typo is", unknown)
	}
}

// TestEveryShippedProfileResolves guards against a profile being advertised in
// AppProfileNames but not actually wired, which would let the dashboard offer a
// platform that loads nothing.
func TestEveryShippedProfileResolves(t *testing.T) {
	t.Parallel()

	names := secwaf.AppProfileNames()
	if len(names) == 0 {
		t.Fatal("no app profiles registered")
	}
	for _, name := range names {
		ex, unknown := secwaf.AppProfileExceptions([]string{name})
		if len(unknown) != 0 {
			t.Errorf("advertised profile %q does not resolve", name)
		}
		if len(ex) == 0 {
			t.Errorf("advertised profile %q loads no exceptions", name)
		}
		for _, e := range ex {
			// gwaf's own tests enforce this upstream; asserting it here means a
			// version bump that loosened it fails in gateon's suite rather than
			// landing an unattributable suppression in a security control.
			if e.RuleID == 0 {
				t.Errorf("profile %q carries an exception matching every rule", name)
			}
			if strings.TrimSpace(e.Note) == "" {
				t.Errorf("profile %q carries an exception with no rationale", name)
			}
		}
	}
}

// TestAppProfilesCompose checks the documented behaviour that an install running
// WordPress behind a Laravel API can enable both, and that enabling one twice is
// not the same as enabling it once plus wasted per-request work.
func TestAppProfilesCompose(t *testing.T) {
	t.Parallel()

	wp, _ := secwaf.AppProfileExceptions([]string{"wordpress"})
	laravel, _ := secwaf.AppProfileExceptions([]string{"laravel"})
	both, _ := secwaf.AppProfileExceptions([]string{"wordpress", "laravel"})

	if len(both) != len(wp)+len(laravel) {
		t.Errorf("composed = %d exceptions; want %d (wordpress) + %d (laravel)",
			len(both), len(wp), len(laravel))
	}

	deduped, _ := secwaf.AppProfileExceptions([]string{"wordpress", "WordPress", "wp"})
	if len(deduped) != len(wp) {
		t.Errorf("three spellings of one profile loaded %d exceptions; want %d",
			len(deduped), len(wp))
	}
}

// TestAppProfileFingerprintSeparatesTyposFromAbsence is the reason
// AppProfileFingerprint exists rather than the caller hashing the normalised
// list. A misspelled profile produces the same ruleset as no profile at all, so
// hashing only what resolved would let the two share a cached engine — and the
// warning that would have told the operator about the typo is emitted once per
// engine build, so they would never see it.
func TestAppProfileFingerprintSeparatesTyposFromAbsence(t *testing.T) {
	t.Parallel()

	none := secwaf.AppProfileFingerprint(nil)
	typo := secwaf.AppProfileFingerprint([]string{"wordpres"})
	if none == typo {
		t.Error("a misspelled profile hashes the same as no profile; the operator would never be warned")
	}

	// The case that must collapse: same profile, different spelling, one engine.
	if a, b := secwaf.AppProfileFingerprint([]string{"WordPress"}),
		secwaf.AppProfileFingerprint([]string{"wordpress"}); a != b {
		t.Errorf("case-different spellings hash differently (%q vs %q); that builds two identical engines", a, b)
	}

	// Order is the operator's, but the engine is the same either way.
	if a, b := secwaf.AppProfileFingerprint([]string{"wordpress", "laravel"}),
		secwaf.AppProfileFingerprint([]string{"wordpress", "laravel"}); a != b {
		t.Error("fingerprint is not stable across calls")
	}
	if a, b := secwaf.AppProfileFingerprint([]string{"wordpress"}),
		secwaf.AppProfileFingerprint([]string{"laravel"}); a == b {
		t.Error("different profiles share a fingerprint")
	}
}
