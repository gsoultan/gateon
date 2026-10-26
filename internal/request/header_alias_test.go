// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"net/http"
	"testing"
)

func TestFoldHeaderNameCollapsesSeparatorsAndCase(t *testing.T) {
	for _, name := range []string{
		"X-Auth-User", "X_Auth_User", "X.Auth.User",
		"x-auth-user", "X_AUTH_USER", "X-Auth_User", "X.Auth-User",
	} {
		if got := FoldHeaderName(name); got != "X_AUTH_USER" {
			t.Errorf("FoldHeaderName(%q) = %q, want X_AUTH_USER", name, got)
		}
	}
}

// StripHeaderAliases must remove every alias a header-folding backend reads as
// the canonical name -- underscore, dot, and mixed-separator forms -- while
// leaving the canonical spelling and unrelated headers untouched. This is the
// mechanism behind CVE-2026-88879 / CVE-2026-88011 (Traefik) and CVE-2026-52845
// (Caddy): the gateway strips only the canonical name, so an alias survives.
func TestStripHeaderAliasesRemovesEveryFoldedForm(t *testing.T) {
	h := http.Header{}
	h.Set("X_Auth_User", "attacker")   // underscore alias
	h.Set("X.Auth.User", "attacker")   // dot alias
	h.Set("X-Auth_User", "attacker")   // mixed alias
	h.Set("X-Real_IP", "10.9.9.9")     // alias of a different managed name
	h.Set("X-Auth-Users", "unrelated") // folds to X_AUTH_USERS, not a match
	h.Set("Content-Type", "application/json")

	StripHeaderAliases(h, "X-Auth-User", "X-Real-IP")

	for _, alias := range []string{"X_Auth_User", "X.Auth.User", "X-Auth_User", "X-Real_IP"} {
		if vals := h.Values(alias); len(vals) != 0 {
			t.Errorf("alias %q survived: %q", alias, vals)
		}
	}
	if got := h.Get("X-Auth-Users"); got != "unrelated" {
		t.Errorf("X-Auth-Users was stripped; it folds to a different name, got %q", got)
	}
	if got := h.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type was stripped, got %q", got)
	}
}

// The canonical spelling is the gateway's to set; the helper must never touch
// it, only the aliases.
func TestStripHeaderAliasesLeavesCanonicalAlone(t *testing.T) {
	h := http.Header{}
	h.Set("X-Auth-User", "gateway-value")
	StripHeaderAliases(h, "X-Auth-User")
	if got := h.Get("X-Auth-User"); got != "gateway-value" {
		t.Errorf("canonical X-Auth-User = %q, want it left in place", got)
	}
}

// A request of ordinary hyphenated headers must be left entirely alone -- the
// fast path that skips any key without '_' or '.'.
func TestStripHeaderAliasesIgnoresPlainHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Forwarded-For", "203.0.113.1")
	h.Set("Accept", "*/*")
	StripHeaderAliases(h, "X-Forwarded-For", "X-Real-IP")
	if len(h) != 2 {
		t.Errorf("plain headers were modified: %v", h)
	}
}
