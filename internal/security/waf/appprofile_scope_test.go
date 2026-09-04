// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"strings"
	"testing"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/ruleset/profiles"
	"github.com/gsoultan/gwaf/types"
)

// Making a profile's scope configurable is exactly the change that could turn a
// profile into the global off-switch it is specifically not allowed to be, so
// the guard rails are tested before the feature.

// TestScopeRefusesPathsThatMatchEverything is the important one.
//
// An exception scoped to "/" or "/*" applies to every request the gateway
// serves, which disables the rule outright — while reading, in a config file or
// a dashboard field, like a narrow setting. That is worse than an obvious
// off-switch, because nobody reviewing it sees a switch.
func TestScopeRefusesPathsThatMatchEverything(t *testing.T) {
	for _, p := range []string{"/", "/*", "*", " / ", "/*  "} {
		scope := AppProfileScope{Paths: []string{p}, Fields: []string{"body"}}
		if err := scope.Validate(); err == nil {
			t.Errorf("path %q was accepted as a profile scope; it matches every "+
				"request, so it turns a scoped exception into a global one", p)
		}
	}
}

// TestScopeRequiresBothHalves pins that a half-configured scope is refused.
//
// Paths with no fields exempts every argument on those paths — broader than
// anything a shipped profile does. Fields with no paths exempts those field
// names everywhere, which is worse still: "body" is a common field name.
func TestScopeRequiresBothHalves(t *testing.T) {
	if err := (AppProfileScope{Paths: []string{"/pastes"}}).Validate(); err == nil {
		t.Error("a scope with paths and no fields was accepted; it would exempt " +
			"every argument on those paths")
	}
	if err := (AppProfileScope{Fields: []string{"body"}}).Validate(); err == nil {
		t.Error("a scope with fields and no paths was accepted; it would exempt " +
			"that field name on every route the gateway serves")
	}
	if err := (AppProfileScope{}).Validate(); err != nil {
		t.Errorf("an empty scope must be valid and mean 'use the profile's own "+
			"defaults', got %v", err)
	}
}

// TestScopeRefusesMidStringWildcards catches a scope that reads as a subtree and
// matches nothing.
//
// gwaf treats a trailing "*" as a prefix and everything else literally, so
// "/api/*/issues" matches no request at all. Silently accepting it produces a
// profile that appears configured and does nothing — the exact failure this
// whole feature exists to fix.
func TestScopeRefusesMidStringWildcards(t *testing.T) {
	scope := AppProfileScope{Paths: []string{"/api/*/issues"}, Fields: []string{"body"}}
	if err := scope.Validate(); err == nil {
		t.Error("a mid-string wildcard was accepted; it matches nothing while " +
			"reading as though it covered a subtree")
	}
}

// TestScopeRefusesFieldWildcards keeps field names exact.
func TestScopeRefusesFieldWildcards(t *testing.T) {
	scope := AppProfileScope{Paths: []string{"/pastes"}, Fields: []string{"body*"}}
	if err := scope.Validate(); err == nil {
		t.Error("a wildcard field name was accepted; keys are matched exactly, so " +
			"this covers less than it appears to")
	}
}

// TestScopeIsBounded pins the ceiling on the cross-product.
//
// Paths and fields both come from configuration and expand multiplicatively. An
// operator pasting long lists into both would otherwise discover the cost by
// watching latency rather than by being told.
func TestScopeIsBounded(t *testing.T) {
	many := make([]string, maxScopeEntries+1)
	for i := range many {
		many[i] = "/p" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	scope := AppProfileScope{Paths: many, Fields: []string{"body"}}
	if err := scope.Validate(); err == nil {
		t.Errorf("a scope with %d paths was accepted, cap is %d", len(many), maxScopeEntries)
	}
}

// TestScopeRepointsProfileExceptions is the feature working.
//
// The rule ids come from the profile untouched — which detections an application
// legitimately trips is upstream's evidence to hold — and only the path and field
// are replaced with the deployment's own.
func TestScopeRepointsProfileExceptions(t *testing.T) {
	original := profiles.IssueTracker()
	if len(original) == 0 {
		t.Fatal("IssueTracker profile is empty; this test has nothing to scope")
	}

	scope := AppProfileScope{
		Paths:  []string{"/pastes", "/tickets/*"},
		Fields: []string{"content", "body"},
	}
	scoped, err := ScopeAppProfileExceptions(original, scope)
	if err != nil {
		t.Fatalf("scope rejected: %v", err)
	}

	originalRules := map[types.RuleID]bool{}
	for _, e := range original {
		originalRules[e.RuleID] = true
	}

	sawPastesContent := false
	for _, e := range scoped {
		if !originalRules[e.RuleID] {
			t.Errorf("scoping invented an exception for rule %d, which the profile "+
				"never named. Which rules are exempt is the profile's decision.", e.RuleID)
		}
		if e.Key == "" {
			continue // keyless entries are passed through untouched, by design
		}
		if e.Path != "/pastes" && e.Path != "/tickets/*" {
			t.Errorf("scoped exception kept path %q, which is not in the configured scope", e.Path)
		}
		if e.Key != "content" && e.Key != "body" {
			t.Errorf("scoped exception kept key %q, which is not in the configured scope", e.Key)
		}
		if e.Path == "/pastes" && e.Key == "content" {
			sawPastesContent = true
		}
	}
	if !sawPastesContent {
		t.Error("no exception was produced for /pastes content, which is the whole " +
			"point of configuring a scope")
	}
}

// TestScopeLeavesKeylessExceptionsAlone pins a deliberate carve-out.
//
// An exception the profile left keyless is already scoped by target rather than
// by field. Narrowing it to the operator's field list could switch off a
// suppression the profile depends on, so those pass through untouched.
func TestScopeLeavesKeylessExceptionsAlone(t *testing.T) {
	in := []rules.Exception{
		{RuleID: 1234, Path: "/orig/*", Target: types.TargetArgs, Note: "keyed"},
		{RuleID: 5678, Path: "/orig/*", Target: types.TargetArgs, Key: "desc", Note: "keyed"},
	}
	in[0].Key = "" // explicit: the first is keyless

	out, err := ScopeAppProfileExceptions(in, AppProfileScope{
		Paths: []string{"/mine"}, Fields: []string{"body"},
	})
	if err != nil {
		t.Fatalf("scope rejected: %v", err)
	}

	found := false
	for _, e := range out {
		if e.RuleID == 1234 {
			found = true
			if e.Path != "/orig/*" || e.Key != "" {
				t.Errorf("a keyless exception was re-scoped to %q/%q; it should pass "+
					"through untouched", e.Path, e.Key)
			}
		}
	}
	if !found {
		t.Error("the keyless exception was dropped entirely")
	}
}

// TestEmptyScopeIsAPassthrough guarantees existing installs are unchanged.
func TestEmptyScopeIsAPassthrough(t *testing.T) {
	original := profiles.IssueTracker()
	out, err := ScopeAppProfileExceptions(original, AppProfileScope{})
	if err != nil {
		t.Fatalf("empty scope errored: %v", err)
	}
	if len(out) != len(original) {
		t.Errorf("an unconfigured scope changed the exception count from %d to %d; "+
			"installs that configured nothing must behave exactly as before",
			len(original), len(out))
	}
}

// TestScopeFingerprintIsOrderIndependent keeps the engine cache correct.
//
// Engines are memoised per config fingerprint. Two routes with the same scope
// written in a different order should share one engine; two routes with
// different scopes must not, or the first to build one wins and the second
// silently inherits exceptions it never configured.
func TestScopeFingerprintIsOrderIndependent(t *testing.T) {
	a := AppProfileScope{Paths: []string{"/a", "/b"}, Fields: []string{"x", "y"}}
	b := AppProfileScope{Paths: []string{"/b", "/a"}, Fields: []string{"y", "x"}}
	if AppProfileScopeFingerprint(a) != AppProfileScopeFingerprint(b) {
		t.Error("the same scope in a different order produced two fingerprints, so " +
			"two identical engines get built")
	}

	c := AppProfileScope{Paths: []string{"/a", "/b"}, Fields: []string{"x", "z"}}
	if AppProfileScopeFingerprint(a) == AppProfileScopeFingerprint(c) {
		t.Error("two different scopes share a fingerprint; the first route to build " +
			"an engine would win and the second would inherit exceptions it never " +
			"configured")
	}

	if AppProfileScopeFingerprint(AppProfileScope{}) != "" {
		t.Error("an unconfigured scope must not perturb the fingerprint of installs " +
			"that never set one")
	}
}
