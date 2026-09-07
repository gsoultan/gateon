// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestNormalizePath covers the resolution itself.
func TestNormalizePath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// Already clean: returned unchanged.
		{"/", "/"},
		{"/api/v1/users", "/api/v1/users"},
		{"/api/v1/users/", "/api/v1/users/"},
		{"/a.b/c.d", "/a.b/c.d"},
		{"/hidden.file", "/hidden.file"},

		// Dot segments resolved.
		{"/public/../admin", "/admin"},
		{"/public/./admin", "/public/admin"},
		{"/a/b/../../admin", "/admin"},
		{"/a/b/../c", "/a/c"},
		{"/./admin", "/admin"},

		// Cannot climb above the root.
		{"/../admin", "/admin"},
		{"/../../../../etc/passwd", "/etc/passwd"},
		{"/..", "/"},

		// Repeated slashes collapse.
		{"//admin", "/admin"},
		{"/a//b///c", "/a/b/c"},

		// A trailing slash is meaningful -- a prefix rule and an exact rule can
		// differ by exactly that character -- so resolution must preserve it.
		{"/a/b/../", "/a/"},
		{"/a//", "/a/"},

		// Degenerate input still yields a rooted path.
		{"", "/"},
		{"admin", "/admin"},
		{"../admin", "/admin"},
	} {
		if got := NormalizePath(tc.in); got != tc.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestNormalizePathDoesNotAllocateForCleanPaths keeps the fast path honest.
//
// This runs on every request. The check for an already-clean path exists so the
// common case costs a scan and no allocation; if that regresses, every request
// pays for a string nobody needed.
func TestNormalizePathDoesNotAllocateForCleanPaths(t *testing.T) {
	paths := []string{"/", "/api/v1/users", "/a/b/c/d/e/f", "/static/app.min.js"}
	got := testing.AllocsPerRun(100, func() {
		for _, p := range paths {
			_ = NormalizePath(p)
		}
	})
	if got != 0 {
		t.Errorf("NormalizePath allocated %v times per run on already-clean paths, "+
			"want 0", got)
	}
}

// trieStore is a RouteStore that only answers what SelectRoute asks.
//
// The embedded interface is nil on purpose: if SelectRoute grows a dependency on
// another method, this panics and says so rather than silently testing something
// else.
type trieStore struct {
	config.RouteStore
	trie *config.PathTrie
}

func (s *trieStore) GetTrieByHost(string) (*config.PathTrie, []*gateonv1.Route) {
	return s.trie, nil
}
func (s *trieStore) GetWildcardTrie() (*config.PathTrie, []*gateonv1.Route) { return nil, nil }

// TestSelectRouteResolvesDotSegments is the regression test for the bypass.
//
// A route carries its middleware chain, so choosing the route is choosing which
// authentication runs. Route selection walked the path one segment at a time and
// treated ".." as an ordinary segment name, so /public/../admin stopped at the
// /public node and was served by /public's route.
//
// Nothing upstream resolved it: Go's HTTP server leaves r.URL.Path exactly as
// sent, and pkg/proxy joins that same string onto the backend URL, where nginx,
// Apache and most frameworks do resolve it and return /admin. So the gateway ran
// /public's chain and the backend served /admin's content. If /admin carried
// authentication and /public did not, it did not run.
//
// The WAF is no help here, because the WAF is itself middleware on the route
// that was chosen -- it is inside the thing being bypassed.
func TestSelectRouteResolvesDotSegments(t *testing.T) {
	trie := config.NewPathTrie()
	public := &gateonv1.Route{Id: "public", Rule: "PathPrefix(`/public`)"}
	admin := &gateonv1.Route{Id: "admin", Rule: "PathPrefix(`/admin`)"}
	trie.Insert("/public", true, public)
	trie.Insert("/admin", true, admin)
	trie.Flatten()
	store := &trieStore{trie: trie}

	for _, tc := range []struct{ path, want string }{
		{"/admin/users", "admin"},
		{"/public/logo.png", "public"},

		// The bypass and its spellings.
		{"/public/../admin/users", "admin"},
		{"/public/../admin", "admin"},
		{"/public/./../admin", "admin"},
		{"/public/a/b/../../../admin", "admin"},
		{"//public/../admin", "admin"},

		// Percent-encoded spellings need no separate handling: r.URL.Path is
		// already decoded by the time routing sees it, so %2e%2e and %2f have
		// become ".." and "/" and resolve like any other dot segment. Asserted
		// rather than assumed, because it is the difference between one fix and
		// three.
		{"/public/%2e%2e/admin", "admin"},
		{"/public%2f..%2fadmin", "admin"},
		{"/public/..%2fadmin", "admin"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			req.Host = "app.example.com"

			got := SelectRoute(req, store)
			if got == nil {
				t.Fatalf("no route matched %q, want %q", tc.path, tc.want)
			}
			if got.Id != tc.want {
				t.Errorf("%q selected route %q, want %q.\n"+
					"The route carries the middleware chain, so selecting the wrong "+
					"one runs the wrong authentication. The backend resolves the dot "+
					"segments and serves what %q points at either way.",
					tc.path, got.Id, tc.want, tc.want)
			}
		})
	}
}

// TestSelectRouteRewritesThePathItRoutedOn pins the second half.
//
// Resolving only for the lookup would leave the proxy forwarding the original
// string, so the gateway would route on one path and the backend would receive
// another. They have to be the same path.
func TestSelectRouteRewritesThePathItRoutedOn(t *testing.T) {
	trie := config.NewPathTrie()
	trie.Insert("/admin", true, &gateonv1.Route{Id: "admin", Rule: "PathPrefix(`/admin`)"})
	trie.Flatten()

	req := httptest.NewRequest("GET", "/public/../admin/users", nil)
	req.Host = "app.example.com"
	SelectRoute(req, &trieStore{trie: trie})

	if req.URL.Path != "/admin/users" {
		t.Errorf("r.URL.Path = %q after routing, want %q; pkg/proxy forwards this "+
			"string, so leaving it unresolved makes the route the gateway chose and "+
			"the path the backend receives two different things",
			req.URL.Path, "/admin/users")
	}
	// The original stays available for the WAF and the access log: normalising
	// must not erase what the client actually sent.
	if req.RequestURI != "/public/../admin/users" {
		t.Errorf("RequestURI = %q, want the client's original; the WAF and the audit "+
			"log need to see the request as sent, not as cleaned up",
			req.RequestURI)
	}
}

// BenchmarkNormalizePath measures what every request now pays.
//
// The clean case is the one that matters: it is what real traffic looks like,
// and it is the cost added to every request to close the bypass.
func BenchmarkNormalizePath(b *testing.B) {
	for _, tc := range []struct{ name, path string }{
		{"clean_short", "/api/v1/users"},
		{"clean_long", "/static/assets/vendor/js/app.bundle.min.js"},
		{"needs_resolving", "/public/../admin/users"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = NormalizePath(tc.path)
			}
		})
	}
}

// TestSelectRouteLeavesPathParametersAlone records a deliberate non-change.
//
// A path segment may legally contain a semicolon, and some servers -- Tomcat and
// other Java containers most notably -- strip ";name=value" path parameters
// before dispatching. Against one of those backends, /admin;x=1 and
// /public/..;/admin are the same bypass shape as the dot-segment case: the
// gateway routes one path and the backend serves another.
//
// It is left alone because, unlike a dot segment, this is not one resource with
// two spellings. RFC 3986 allows a semicolon in a path segment, so /admin;x=1
// and /admin are different paths to most backends, and stripping would break the
// ones that mean it literally. Which behaviour is correct depends on a backend
// the gateway does not know about.
//
// Recorded rather than silently accepted, so it is a decision with a reason
// attached and not a gap someone finds later.
func TestSelectRouteLeavesPathParametersAlone(t *testing.T) {
	if got := NormalizePath("/admin;x=1"); got != "/admin;x=1" {
		t.Errorf("NormalizePath(\"/admin;x=1\") = %q; path parameters are being "+
			"stripped now. That closes a bypass against Tomcat-style backends and "+
			"breaks any backend that means the semicolon literally — make sure that "+
			"trade was made deliberately and update this test.", got)
	}
	if got := NormalizePath("/public/..;/admin"); got != "/public/..;/admin" {
		t.Errorf("NormalizePath(\"/public/..;/admin\") = %q, want it unchanged; "+
			"\"..;\" is not a dot segment to this layer", got)
	}
}
