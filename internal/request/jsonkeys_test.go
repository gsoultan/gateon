// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"strings"
	"testing"
)

func TestAmbiguousJSONKey(t *testing.T) {
	cases := []struct {
		doc     string
		onlyTop bool
		key     string
		dup     bool
	}{
		{`{"query":"a","QUERY":"b"}`, true, "QUERY", true},
		{`{"query":"a","query":"b"}`, true, "query", true},
		{`{"query":"a","query":"b"}`, true, "query", true},
		{`{"k":1,"K":2}`, false, "K", true}, // Kelvin sign folds to k, as encoding/json matches it
		{`{"":1,"":2}`, false, "", true},
		{`{"a":{"b":1},"A":2}`, false, "A", true},
		{`{"a":[{"x":1},{"x":2}],"b":{"x":"x"}}`, false, "", false},
		{`{"a":{"x":1,"X":2}}`, true, "", false},
		{`{"a":{"x":1,"X":2}}`, false, "X", true},
		{`[{"x":1},{"X":2}]`, false, "", false},
		{`[{"x":1,"X":2}]`, false, "X", true},
		{`{"a":"b","b":"a","c":["a","b"],"d":null}`, false, "", false},
		{`"query"`, true, "", false},
		{`{"a":{},"b":[],"c":{"d":[[]]},"e":1}`, false, "", false},
	}
	for _, c := range cases {
		key, dup, err := AmbiguousJSONKey([]byte(c.doc), c.onlyTop)
		if err != nil {
			t.Errorf("%s: %v", c.doc, err)
			continue
		}
		if dup != c.dup || key != c.key {
			t.Errorf("%s onlyTop=%v: got (%q, %v), want (%q, %v)", c.doc, c.onlyTop, key, dup, c.key, c.dup)
		}
	}
}

func TestAmbiguousJSONKeyBoundsDepth(t *testing.T) {
	doc := strings.Repeat("[", maxJSONKeyDepth+2) + strings.Repeat("]", maxJSONKeyDepth+2)
	if _, _, err := AmbiguousJSONKey([]byte(doc), false); err == nil {
		t.Fatal("a document past the depth bound was walked without error")
	}
}
