// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Lookup split the request path into a slice of segments on every request to
// walk the trie once. It now cuts segments off the path as it goes, which
// must give the same answer for every shape a path takes: exact and prefix
// matches, doubled and trailing slashes, and the root.
func TestPathTrieLookupWalksSegmentsWithoutSplitting(t *testing.T) {
	trie := NewPathTrie()
	exact := &gateonv1.Route{Id: "exact"}
	prefix := &gateonv1.Route{Id: "prefix"}
	root := &gateonv1.Route{Id: "root"}
	trie.Insert("/api/v1/items", false, exact)
	trie.Insert("/api", true, prefix)
	trie.Insert("/", false, root)
	trie.Flatten()

	cases := []struct {
		path string
		want []string
	}{
		{"/api/v1/items", []string{"exact", "prefix"}},
		{"/api/v1/items/", []string{"exact", "prefix"}},
		{"/api//v1///items", []string{"exact", "prefix"}},
		{"/api/v1/other", []string{"prefix"}},
		{"/api", []string{"prefix"}},
		{"/other", nil},
		{"/", []string{"root"}},
		{"", []string{"root"}},
	}
	for _, tc := range cases {
		got := trie.Lookup(tc.path)
		ids := make([]string, 0, len(got))
		for _, r := range got {
			ids = append(ids, r.Id)
		}
		if len(ids) != len(tc.want) {
			t.Fatalf("Lookup(%q) = %v, want %v", tc.path, ids, tc.want)
		}
		for _, w := range tc.want {
			found := false
			for _, id := range ids {
				found = found || id == w
			}
			if !found {
				t.Fatalf("Lookup(%q) = %v, want %v", tc.path, ids, tc.want)
			}
		}
	}

	if n := testing.AllocsPerRun(100, func() { trie.Lookup("/api/v1/items") }); n != 0 {
		t.Fatalf("Lookup allocated %v times per call, want 0", n)
	}
}
