// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gsoultan/gwaf/rules"
)

// An app profile says *which rules* an application's own content trips. Where
// that content lives is a different question, and it is the deployment's answer
// rather than the profile's.
//
// gwaf ships IssueTracker scoped to `Path: "/rest/api/*"` with `Key` in
// `description|body` — Jira's shape, and its doc comment says outright that "the
// paths are examples and are meant to be edited". Nothing edited them. Gateon
// passed the profile through verbatim, so an operator running a paste service on
// /pastes, a support desk on /tickets or a wiki anywhere at all selected
// `issue_tracker`, saw it listed in the dashboard, and got nothing: every
// exception was scoped to a path their application does not serve.
//
// That was measured rather than assumed. Tagging the developer-tool samples in
// the false-positive corpus with `issue_tracker` and re-running changed no
// verdict at all — eight of the twelve refusals at paranoia 1 stayed refused.
//
// So the profile keeps deciding which rules are exempt, which is the security
// half and belongs upstream where the evidence is, and the deployment supplies
// the paths and fields, which is the half only it can know.

const (
	// maxScopedExceptions bounds the cross-product.
	//
	// Paths and fields both come from configuration, and the expansion is
	// rules × paths × fields. An operator pasting a long list into both boxes
	// would otherwise build an exception set large enough to slow every request
	// on the route, and would find out by watching latency rather than by being
	// told.
	maxScopedExceptions = 2000

	// maxScopeEntries caps each input list on its own, so the error names the
	// list that is too long rather than a product nobody can attribute.
	maxScopeEntries = 64
)

// AppProfileScope is the deployment's answer to "where does this application
// keep the content that trips those rules".
//
// Both lists must be non-empty to take effect. A scope with paths and no fields
// would exempt every argument on those paths, which is a great deal broader than
// anything a profile ships and is the shape a mistake takes.
type AppProfileScope struct {
	// Paths are request paths, with a trailing "*" for a subtree — the same
	// syntax gwaf's own exceptions use.
	Paths []string

	// Fields are argument, field or header names: the boxes the application
	// stores and displays.
	Fields []string
}

// IsZero reports whether no scope was configured, in which case each profile's
// shipped defaults apply unchanged.
func (s AppProfileScope) IsZero() bool { return len(s.Paths) == 0 && len(s.Fields) == 0 }

// Validate rejects a scope that would widen an exception past what a profile is
// allowed to be.
//
// The invariant this protects is the one TestAppProfileIsScopedNotAGlobalOff
// already pins for the shipped profiles: selecting a platform must never become
// a way to switch detection off. Making the scope configurable is exactly the
// change that could break it, so the validation lives next to the feature rather
// than in a review checklist.
func (s AppProfileScope) Validate() error {
	if s.IsZero() {
		return nil
	}
	if len(s.Paths) == 0 {
		return fmt.Errorf("app profile scope names fields but no paths; that would " +
			"exempt those fields on every route the gateway serves")
	}
	if len(s.Fields) == 0 {
		return fmt.Errorf("app profile scope names paths but no fields; that would " +
			"exempt every argument on those paths, which is broader than any " +
			"shipped profile")
	}
	if len(s.Paths) > maxScopeEntries {
		return fmt.Errorf("app profile scope has %d paths, limit is %d", len(s.Paths), maxScopeEntries)
	}
	if len(s.Fields) > maxScopeEntries {
		return fmt.Errorf("app profile scope has %d fields, limit is %d", len(s.Fields), maxScopeEntries)
	}

	for _, p := range s.Paths {
		if err := validateScopePath(p); err != nil {
			return err
		}
	}
	for _, f := range s.Fields {
		if strings.TrimSpace(f) == "" {
			return fmt.Errorf("app profile scope has an empty field name")
		}
		if strings.Contains(f, "*") {
			return fmt.Errorf("app profile scope field %q contains a wildcard; field "+
				"names are matched exactly, and a wildcard here reads as covering "+
				"more than it does", f)
		}
	}
	return nil
}

// validateScopePath refuses the paths that are not a scope at all.
//
// "/*" and "/" cover the whole site, and "*" covers it twice. An exception
// scoped to any of them applies everywhere, which turns a profile into the
// global off-switch it is specifically not allowed to be — and it would look
// like a narrow configuration while doing it, which is the part that makes it
// worth an error rather than a warning.
func validateScopePath(p string) error {
	trimmed := strings.TrimSpace(p)
	switch trimmed {
	case "":
		return fmt.Errorf("app profile scope has an empty path")
	case "*", "/", "/*":
		return fmt.Errorf("app profile scope path %q matches every request; a "+
			"profile scopes exceptions to one application's routes and must not "+
			"become a way to disable detection globally", p)
	}
	if !strings.HasPrefix(trimmed, "/") {
		return fmt.Errorf("app profile scope path %q must start with \"/\"", p)
	}
	if i := strings.Index(trimmed, "*"); i >= 0 && i != len(trimmed)-1 {
		return fmt.Errorf("app profile scope path %q has a \"*\" that is not at the "+
			"end; gwaf treats a trailing star as a prefix match and everything else "+
			"literally, so this would match nothing and read as though it matched a "+
			"subtree", p)
	}
	return nil
}

// ScopeAppProfileExceptions re-points a profile's exceptions at the operator's
// own paths and fields.
//
// The rule ids and targets come from the profile untouched — those encode which
// detections this class of application legitimately trips, which is upstream's
// evidence to hold. Only Path and Key are replaced. An exception whose Key the
// profile left empty is left alone: a keyless entry is already scoped by target
// rather than by field, and narrowing it to the operator's field list could turn
// off a suppression the profile relies on.
//
// Returns the input unchanged when the scope is empty, so an install that has
// not configured anything keeps exactly the behaviour it has today.
func ScopeAppProfileExceptions(exceptions []rules.Exception, scope AppProfileScope) ([]rules.Exception, error) {
	if scope.IsZero() || len(exceptions) == 0 {
		return exceptions, nil
	}
	if err := scope.Validate(); err != nil {
		return nil, err
	}

	paths := normaliseScopeList(scope.Paths)
	fields := normaliseScopeList(scope.Fields)

	// Count before building: the failure should name the size, not manifest as
	// an engine that takes a second to construct and a route that is slow after.
	var keyed int
	for _, e := range exceptions {
		if e.Key != "" {
			keyed++
		}
	}
	if total := keyed * len(paths) * len(fields); total > maxScopedExceptions {
		return nil, fmt.Errorf("app profile scope expands to %d exceptions "+
			"(%d rules x %d paths x %d fields), limit is %d; narrow the paths or "+
			"the fields", total, keyed, len(paths), len(fields), maxScopedExceptions)
	}

	out := make([]rules.Exception, 0, keyed*len(paths)*len(fields)+(len(exceptions)-keyed))
	for _, e := range exceptions {
		if e.Key == "" {
			out = append(out, e)
			continue
		}
		for _, p := range paths {
			for _, f := range fields {
				scoped := e
				scoped.Path = p
				scoped.Key = f
				scoped.Note = e.Note + " (scoped to this deployment's " + p + " " + f + ")"
				out = append(out, scoped)
			}
		}
	}
	return out, nil
}

// normaliseScopeList trims, drops blanks and de-duplicates while keeping order.
func normaliseScopeList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// AppProfileScopeFingerprint renders a scope for the engine cache key.
//
// Engines are memoised per config fingerprint, so a field left out of the key
// means the first route to build an engine wins and every later route with a
// different policy silently inherits it (mem:gwaf_v040 records this happening).
// A scope decides which requests an exception covers, so two routes differing
// only in it must not share an engine.
//
// Sorted, because the scope is a set: two operators writing the same paths in a
// different order should get one engine, not two.
func AppProfileScopeFingerprint(scope AppProfileScope) string {
	if scope.IsZero() {
		return ""
	}
	paths := append([]string(nil), normaliseScopeList(scope.Paths)...)
	fields := append([]string(nil), normaliseScopeList(scope.Fields)...)
	sort.Strings(paths)
	sort.Strings(fields)
	return strings.Join(paths, ",") + "|" + strings.Join(fields, ",")
}
