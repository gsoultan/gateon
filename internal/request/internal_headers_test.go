// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"net/http"
	"testing"
)

// TestInternalHeaderIndexAgreesWithTheList pins the switch to the array: a
// name added to one and not the other would be listed and never stripped.
func TestInternalHeaderIndexAgreesWithTheList(t *testing.T) {
	for i, name := range InternalHeaders {
		if http.CanonicalHeaderKey(name) != name {
			t.Errorf("%q is not in canonical form, so no request header can equal it", name)
		}
		if len(name) < minInternalHeaderLen || name[0] != 'X' {
			t.Errorf("%q would be skipped by the length and first-byte check", name)
		}
		if got := internalHeaderIndex(name); got != i {
			t.Errorf("internalHeaderIndex(%q) = %d, want %d", name, got, i)
		}
	}
}

func TestStripInternalHeadersRemovesEverySpelling(t *testing.T) {
	for _, name := range InternalHeaders {
		for _, spelling := range []string{
			name,
			replaceByte(name, '-', '_'),
			replaceByte(name, '-', '.'),
		} {
			h := http.Header{}
			// Set directly: an alias is not something CanonicalHeaderKey
			// produces, it arrives as the client typed it.
			h[http.CanonicalHeaderKey(spelling)] = []string{"/admin"}
			h.Set("Accept", "*/*")
			if found := stripInternalHeaders(h, 0); found == 0 {
				t.Errorf("%q was not reported", spelling)
			}
			if len(h) != 1 || h.Get("Accept") == "" {
				t.Errorf("%q survived, or an ordinary header did not: %v", spelling, h)
			}
		}
	}
}

func TestStripInternalHeadersLeavesOrdinaryHeaders(t *testing.T) {
	h := http.Header{}
	for _, name := range []string{
		"X-Forwarded-For", "X-Request-Id", "Authorization", "X-Original-Filename",
		"X-Http-Methods", "Content-Type", "X_Custom_Thing",
	} {
		h[name] = []string{"v"}
	}
	before := len(h)
	if found := stripInternalHeaders(h, 0); found != 0 || len(h) != before {
		t.Errorf("found=%b, %d of %d headers left", found, len(h), before)
	}
}

func TestForwardInternalHeadersExemptsOnlyWhatItNames(t *testing.T) {
	exempt := parseForwardInternalHeaders(" x-http-method-override , not-a-header,")
	h := http.Header{
		"X-Http-Method-Override":  {"DELETE"},
		"X_http_method_override":  {"DELETE"},
		"X-Middleware-Subrequest": {"middleware"},
	}
	stripInternalHeaders(h, exempt)
	if h.Get("X-Http-Method-Override") == "" || len(h["X_http_method_override"]) == 0 {
		t.Errorf("the exempted header was stripped: %v", h)
	}
	if h.Get("X-Middleware-Subrequest") != "" {
		t.Errorf("a header nobody exempted was forwarded: %v", h)
	}
}

func TestStripInternalHeadersAllocatesNothingOnAnOrdinaryRequest(t *testing.T) {
	h := http.Header{
		"Accept": {"*/*"}, "User-Agent": {"curl/8"}, "Cookie": {"a=b"},
		"X-Forwarded-For": {"198.51.100.4"}, "Accept-Encoding": {"gzip"},
	}
	if n := testing.AllocsPerRun(200, func() { stripInternalHeaders(h, 0) }); n != 0 {
		t.Errorf("an ordinary request allocated %.0f times", n)
	}
}

func replaceByte(s string, from, to byte) string {
	b := []byte(s)
	for i := range b {
		if b[i] == from {
			b[i] = to
		}
	}
	return string(b)
}

func BenchmarkStripInternalHeaders(b *testing.B) {
	h := http.Header{
		"Accept": {"*/*"}, "User-Agent": {"curl/8"}, "Cookie": {"a=b"},
		"X-Forwarded-For": {"198.51.100.4"}, "Accept-Encoding": {"gzip"},
		"Accept-Language": {"en"}, "Referer": {"https://example.com/"}, "Host": {"example.com"},
	}
	b.ReportAllocs()
	for b.Loop() {
		stripInternalHeaders(h, 0)
	}
}
