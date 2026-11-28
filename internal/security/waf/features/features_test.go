// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package features

import (
	"slices"
	"strconv"
	"testing"

	"github.com/gsoultan/gateon/internal/security/waf/corpus"
	"github.com/gsoultan/gwaf/types"
)

func newScanner(t testing.TB) *Scanner {
	t.Helper()
	s, err := NewScanner(4)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func field(t *testing.T, r Row, column string) string {
	t.Helper()
	v, ok := r.Fields()[column]
	if !ok {
		t.Fatalf("no column %q", column)
	}
	return v
}

func TestColumnsAreUniqueAndEveryRowHasThemAll(t *testing.T) {
	seen := map[string]bool{LabelColumn: true}
	for _, c := range Columns {
		if seen[c] {
			t.Fatalf("column %q is named twice, or is the label", c)
		}
		seen[c] = true
	}
	r := Extract(Input{}, nil)
	if len(r.Values()) != len(Columns) {
		t.Fatalf("a row has %d values for %d columns", len(r.Values()), len(Columns))
	}
	for i, v := range r.Values() {
		if v == "" {
			t.Errorf("column %q is empty for an empty sample", Columns[i])
		}
	}
}

// A model is taught on rows from one process and asked with rows from
// another. A sample whose parameters come out of a map in another order
// must give the same row, or the two would disagree without a sound.
func TestTheSameSampleGivesTheSameRow(t *testing.T) {
	e := &corpus.Entry{Method: "get", Target: "/a/b.php?x=%2541&y=1", Args: map[string]string{}}
	for i := range 40 {
		e.Args["k"+strconv.Itoa(i)] = "v" + strconv.Itoa(i%7) + "abcdefghij"[:i%10]
	}
	// Two longest values of one length and different entropy: which one is
	// "the longest" must not depend on the map.
	e.Args["tie1"], e.Args["tie2"] = "zzzzzzzzzzzz", "zyxwvutsrqpo"
	want := Extract(Input{Entry: e, Why: "matched", Rules: []uint32{1, 2}}, nil).Values()
	if got := want[index[colEntropy]]; got != "3.585" {
		t.Fatalf("entropy_longest = %s: the tie went to whichever value the map gave first", got)
	}
	for range 50 {
		got := Extract(Input{Entry: e, Why: "matched", Rules: []uint32{1, 2}}, nil).Values()
		if !slices.Equal(got, want) {
			t.Fatalf("rows differ:\n%v\n%v", got, want)
		}
	}
}

func TestScannerCountsWhatTheStrictRulesFind(t *testing.T) {
	s := newScanner(t)
	cases := []struct {
		name   string
		entry  *corpus.Entry
		column string
	}{
		{"sqli", &corpus.Entry{Target: "/items", Args: map[string]string{"id": "1' UNION SELECT password FROM users--"}}, colSQLi},
		{"xss", &corpus.Entry{Target: "/search", Args: map[string]string{"q": "<script>alert(document.cookie)</script>"}}, colXSS},
		{"query in target", &corpus.Entry{Target: "/items?id=1%27%20OR%201%3D1--"}, colSQLi},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := s.Scan(tc.entry)
			seen := map[uint32]bool{}
			for _, h := range hits {
				if seen[h.Rule] {
					t.Fatalf("rule %d is counted twice: %v", h.Rule, hits)
				}
				seen[h.Rule] = true
			}
			r := Extract(Input{Entry: tc.entry}, hits)
			if n, _ := strconv.Atoi(field(t, r, tc.column)); n < 1 {
				t.Fatalf("%s = %s, want at least 1 (hits %v)", tc.column, field(t, r, tc.column), hits)
			}
			if c, _ := strconv.Atoi(field(t, r, colMaxConfidence)); c < int(types.Low) {
				t.Fatalf("max_confidence = %d", c)
			}
		})
	}
}

func TestScannerFindsNothingInAnOrdinaryRequest(t *testing.T) {
	s := newScanner(t)
	e := &corpus.Entry{Method: "GET", Target: "/v1/routes", Args: map[string]string{"page": "1", "pageSize": "10"},
		Headers: map[string]string{"User-Agent": "Mozilla/5.0", "Accept": "application/json"}}
	hits := s.Scan(e)
	if len(hits) != 0 {
		t.Fatalf("hits = %v", hits)
	}
	r := Extract(Input{Entry: e, Why: "sampled"}, hits)
	for col, want := range map[string]string{
		colMaxConfidence: "-1", colAnomaly: "0", colSQLi: "0", colWhy: "sampled",
		colAgent: "browser", colAccept: "no", colArgs: "2", colPathDepth: "2", colMethod: "GET",
	} {
		if got := field(t, r, col); got != want {
			t.Errorf("%s = %q, want %q", col, got, want)
		}
	}
}

func TestShapeColumns(t *testing.T) {
	e := &corpus.Entry{
		Method: "TRACE", Target: "/files/x.weird?f=..%2F..%2Fetc%2Fpasswd%00&g=%2541",
		Headers: map[string]string{"user-agent": "sqlmap/1.7", "Content-Type": "text/plain"},
	}
	r := Extract(Input{Entry: e, Why: "anything else"}, nil)
	for col, want := range map[string]string{
		colMethod: "other", colExtension: "other", colDouble: "yes", colControl: "yes",
		colAgent: "tool", colAccept: "yes", colContentType: "yes", colWhy: "none", colArgs: "2",
	} {
		if got := field(t, r, col); got != want {
			t.Errorf("%s = %q, want %q", col, got, want)
		}
	}
	if v, _ := strconv.ParseFloat(field(t, r, colEncoded), 64); v <= 0.2 {
		t.Errorf("encoded_share = %v, want most of the bytes", v)
	}
	if got := Extract(Input{Entry: &corpus.Entry{Target: "/a/../../b"}}, nil); field(t, got, colTraversal) != "yes" {
		t.Errorf("dot_segments missed a raw ../")
	}
}

func TestRequestURIKeepsAQueryAlreadyInTheTarget(t *testing.T) {
	if got := RequestURI("/a?x=1", map[string]string{"y": "2"}); got != "/a?x=1&y=2" {
		t.Fatalf("got %q", got)
	}
	if got := RequestURI("/a", nil); got != "/a" {
		t.Fatalf("got %q", got)
	}
}

// closed is every value a column that is not a number may hold. A value
// outside it would be text the client wrote, which ADR 0108 keeps out of
// every row.
var closed = map[string]bool{
	"yes": true, "no": true, "none": true, "other": true, "matched": true, "outside_schema": true,
	"sampled": true, "missing": true, "browser": true, "tool": true,
}

func init() {
	for m := range methods {
		closed[m] = true
	}
	for x := range extensions {
		closed[x] = true
	}
}

// FuzzExtract holds the claim the package makes: whatever a client sends,
// a row holds numbers and words from closed lists, never the client's text.
func FuzzExtract(f *testing.F) {
	f.Add("GET", "/a/b.php?x=1", "q", "1' OR 1=1--", "User-Agent", "curl/8", "matched")
	f.Add("P\x00ST", "/%25%2e%2e/", "", "\xff\xfe", "", "", "")
	s := newScanner(f)
	f.Fuzz(func(t *testing.T, method, target, k, v, hk, hv, why string) {
		e := &corpus.Entry{Method: method, Target: target, Args: map[string]string{k: v}, Headers: map[string]string{hk: hv}}
		r := Extract(Input{Entry: e, Why: why}, s.Scan(e))
		for i, val := range r.Values() {
			if _, err := strconv.ParseFloat(val, 64); err == nil {
				continue
			}
			if !closed[val] {
				t.Fatalf("column %q holds %q, which is not a number or a closed value", Columns[i], val)
			}
		}
	})
}

func BenchmarkExtract(b *testing.B) {
	s := newScanner(b)
	e := &corpus.Entry{Method: "GET", Target: "/api/v1/items", Args: map[string]string{"page": "2", "q": "red shoes", "sort": "-price"},
		Headers: map[string]string{"User-Agent": "Mozilla/5.0", "Accept": "application/json"}}
	b.ReportAllocs()
	for b.Loop() {
		_ = Extract(Input{Entry: e, Why: "sampled"}, s.Scan(e))
	}
}
