// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"testing"
	"unicode/utf8"
)

// SafeText must leave storable text alone -- including multi-byte text, which
// is not hostile -- and turn exactly the two things Postgres refuses into
// U+FFFD. The stores that call it are tested against a real Postgres; this pins
// the mapping and the no-allocation claim the telemetry writer relies on.
func TestSafeText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"GET /index.html", "GET /index.html"},
		{"/café/東京", "/café/東京"},
		{"/a\x00b", "/a�b"},
		{"sqlmap\xff", "sqlmap�"},
		{"\xff\xfe\x00", "��"},
		{"", ""},
	}
	for _, tc := range cases {
		got := SafeText(tc.in)
		if got != tc.want {
			t.Errorf("SafeText(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("SafeText(%q) is still not valid UTF-8", tc.in)
		}
	}
	if n := testing.AllocsPerRun(100, func() { _ = SafeText("/café/東京?q=1") }); n != 0 {
		t.Errorf("SafeText allocated %v times for text that needed no change", n)
	}
}
