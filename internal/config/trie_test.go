// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// PathTrie decides which routes are candidates for a request path, and a route
// carries its middleware chain -- including whatever authentication is on it.
// Picking the wrong route is therefore not a routing bug, it is whichever
// security control that route was carrying.
//
// It shipped with every function at 0% coverage.

func route(id, rule string, priority int32) *gateonv1.Route {
	return &gateonv1.Route{Id: id, Rule: rule, Priority: priority}
}

// build inserts routes and flattens, which is the required order.
func build(t *testing.T, in []struct {
	path     string
	isPrefix bool
	rt       *gateonv1.Route
}) *PathTrie {
	t.Helper()
	tr := NewPathTrie()
	for _, e := range in {
		tr.Insert(e.path, e.isPrefix, e.rt)
	}
	tr.Flatten()
	return tr
}

func ids(routes []*gateonv1.Route) []string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, r.Id)
	}
	return out
}

func has(routes []*gateonv1.Route, id string) bool {
	for _, r := range routes {
		if r.Id == id {
			return true
		}
	}
	return false
}

// TestTrieExactAndPrefixMatching is the baseline.
func TestTrieExactAndPrefixMatching(t *testing.T) {
	tr := build(t, []struct {
		path     string
		isPrefix bool
		rt       *gateonv1.Route
	}{
		{"/api", true, route("api-prefix", "PathPrefix(`/api`)", 0)},
		{"/api/health", false, route("health-exact", "Path(`/api/health`)", 0)},
		{"/admin", true, route("admin-prefix", "PathPrefix(`/admin`)", 0)},
	})

	t.Run("exact path sees its own route and inherited prefixes", func(t *testing.T) {
		got := tr.Lookup("/api/health")
		if !has(got, "health-exact") || !has(got, "api-prefix") {
			t.Errorf("Lookup(/api/health) = %v, want both the exact route and the "+
				"ancestor prefix", ids(got))
		}
	})

	t.Run("a deeper path sees only prefixes", func(t *testing.T) {
		got := tr.Lookup("/api/v1/users")
		if !has(got, "api-prefix") {
			t.Errorf("Lookup(/api/v1/users) = %v, want the /api prefix route", ids(got))
		}
		if has(got, "health-exact") {
			t.Error("an exact route for /api/health was offered for /api/v1/users; an " +
				"exact rule that matches a different path is the whole point of it " +
				"being exact")
		}
	})

	t.Run("an unrelated branch sees nothing", func(t *testing.T) {
		if got := tr.Lookup("/public/assets"); len(got) != 0 {
			t.Errorf("Lookup(/public/assets) = %v, want no candidates", ids(got))
		}
	})

	t.Run("routes do not leak across siblings", func(t *testing.T) {
		if got := tr.Lookup("/admin/users"); has(got, "api-prefix") {
			t.Errorf("Lookup(/admin/users) = %v; /api's prefix route must not be a "+
				"candidate for /admin", ids(got))
		}
	})
}

// TestTrieNormalisesSlashes covers the spellings of the same path.
func TestTrieNormalisesSlashes(t *testing.T) {
	tr := build(t, []struct {
		path     string
		isPrefix bool
		rt       *gateonv1.Route
	}{{"/api/health", false, route("health", "Path(`/api/health`)", 0)}})

	for _, p := range []string{"/api/health", "api/health", "/api/health/", "//api//health//"} {
		if got := tr.Lookup(p); !has(got, "health") {
			t.Errorf("Lookup(%q) = %v, want the route; these are the same path and a "+
				"client chooses the spelling", p, ids(got))
		}
	}
}

// TestTrieOrdersCandidatesByPriorityThenSpecificity pins the tie-breaks.
//
// The router takes the first candidate that matches, so this ordering is the
// decision. Two routes with the same priority and an unstable order would mean a
// request landing on a different chain between restarts.
func TestTrieOrdersCandidatesByPriorityThenSpecificity(t *testing.T) {
	tr := build(t, []struct {
		path     string
		isPrefix bool
		rt       *gateonv1.Route
	}{
		{"/api", true, route("low", "PathPrefix(`/api`)", 1)},
		{"/api", true, route("high", "PathPrefix(`/api`)", 100)},
		{"/api", true, route("mid", "PathPrefix(`/api`)", 50)},
	})

	got := ids(tr.Lookup("/api/x"))
	want := []string{"high", "mid", "low"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("order = %v, want %v — the router takes the first match, so this "+
				"ordering is which route wins", got, want)
		}
	}
}

// TestTrieOrderIsDeterministic covers the final tie-break.
func TestTrieOrderIsDeterministic(t *testing.T) {
	mk := func() []string {
		tr := build(t, []struct {
			path     string
			isPrefix bool
			rt       *gateonv1.Route
		}{
			{"/api", true, route("zebra", "PathPrefix(`/api`)", 10)},
			{"/api", true, route("alpha", "PathPrefix(`/api`)", 10)},
			{"/api", true, route("mango", "PathPrefix(`/api`)", 10)},
		})
		return ids(tr.Lookup("/api/x"))
	}
	first := mk()
	for i := 0; i < 5; i++ {
		got := mk()
		for j := range first {
			if got[j] != first[j] {
				t.Fatalf("run %d gave %v, first run gave %v; equal-priority routes must "+
					"resolve the same way every time or a request lands on a different "+
					"middleware chain between restarts", i, got, first)
			}
		}
	}
}

// TestTriePrefixesAreInheritedDownTheTree covers the flatten step.
func TestTriePrefixesAreInheritedDownTheTree(t *testing.T) {
	tr := build(t, []struct {
		path     string
		isPrefix bool
		rt       *gateonv1.Route
	}{
		{"/", true, route("root", "PathPrefix(`/`)", 0)},
		{"/a", true, route("a", "PathPrefix(`/a`)", 0)},
		{"/a/b/c", false, route("abc", "Path(`/a/b/c`)", 0)},
	})

	got := tr.Lookup("/a/b/c")
	for _, want := range []string{"root", "a", "abc"} {
		if !has(got, want) {
			t.Errorf("Lookup(/a/b/c) = %v, missing %q; a prefix route applies to every "+
				"path beneath it", ids(got), want)
		}
	}
}

// TestTrieLookupBeforeFlattenReturnsNothing records a footgun.
//
// Flatten builds the lists Lookup reads. Skipping it does not degrade matching,
// it silences it: every lookup returns nothing and every request 404s, with a
// trie that is fully populated and looks correct in a debugger.
func TestTrieLookupBeforeFlattenReturnsNothing(t *testing.T) {
	tr := NewPathTrie()
	tr.Insert("/api", true, route("api", "PathPrefix(`/api`)", 0))

	if got := tr.Lookup("/api/x"); len(got) != 0 {
		t.Skip("Lookup now works without Flatten; this test recorded that it did not")
	}
	tr.Flatten()
	if got := tr.Lookup("/api/x"); len(got) == 0 {
		t.Error("Flatten did not make the inserted route reachable")
	}
}

// TestTrieTreatsDotSegmentsAsOrdinarySegments records what this layer does and,
// more importantly, what it does not.
//
// Lookup walks the path one segment at a time. There is no child named "..", so
// a lookup of /public/../admin stops at the /public node and returns its prefix
// routes -- the request is matched against /public.
//
// That is correct for a trie and wrong for a gateway. Resolving the path is the
// router's job, and it does it before calling Lookup: see
// TestSelectRouteResolvesDotSegments in internal/router, which is the regression
// test for the bypass this would otherwise be. Pinned here so that if the trie
// is ever changed to resolve segments itself, the two layers do not quietly
// start doing it twice.
func TestTrieTreatsDotSegmentsAsOrdinarySegments(t *testing.T) {
	tr := build(t, []struct {
		path     string
		isPrefix bool
		rt       *gateonv1.Route
	}{
		{"/public", true, route("public", "PathPrefix(`/public`)", 0)},
		{"/admin", true, route("admin", "PathPrefix(`/admin`)", 0)},
	})

	got := tr.Lookup("/public/../admin")
	if !has(got, "public") || has(got, "admin") {
		t.Errorf("Lookup(/public/../admin) = %v; this layer is expected to walk \"..\" "+
			"as an ordinary segment and stop at /public. If that changed, the "+
			"router's normalisation is now redundant or doubled — check both.",
			ids(got))
	}
}
