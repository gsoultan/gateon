// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// CodeQL flagged go/incorrect-integer-conversion at four sites that parsed a
// query parameter with strconv.Atoi and then converted to int32 for the RPC.
// Atoi returns an int, so on a 64-bit build the parse succeeds for values no
// int32 can hold and the conversion silently wraps:
//
//	"4294967297"  -> parses as 4294967297 -> int32 -> 1
//	"2147483648"  -> parses as 2147483648 -> int32 -> -2147483648
//
// The guards at those sites tested the parsed value (`l > 0`, `o >= 0`), which
// is a different number from the one that was sent. A negative limit or offset
// reached the query layer.
//
// This is the same defect the pagination helper was written for, so these
// handlers now use it. What follows pins the arithmetic rather than the
// handlers, because the handlers need a full service to construct — the
// conversion is the bug, and it is what is tested.

// parseAsHandlersUsedTo reproduces the old parse so the difference is visible
// rather than asserted.
func parseAsHandlersUsedTo(s string, def int32) int32 {
	if s == "" {
		return def
	}
	if v, err := strconv.Atoi(s); err == nil && v > 0 {
		return int32(v) // #nosec G115 -- reproducing the defect under test
	}
	return def
}

func TestIntegerConversionOverflowIsRejectedNotWrapped(t *testing.T) {
	tests := []struct {
		name  string
		input string
		// what the old Atoi+int32() path produced
		wrapped int32
	}{
		{name: "2^32+1 wraps to a small positive", input: "4294967297", wrapped: 1},
		{name: "MaxInt32+1 wraps negative", input: "2147483648", wrapped: -2147483648},
		{name: "2^32 wraps to zero", input: "4294967296", wrapped: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The old path really did produce these values; if it does not, the
			// premise of this test has changed and it should be revisited.
			if got := parseAsHandlersUsedTo(tt.input, 50); got != tt.wrapped {
				t.Fatalf("premise check: old parse of %q gave %d, expected the wrap to %d",
					tt.input, got, tt.wrapped)
			}

			got := boundedInt32(tt.input, maxPageSize)
			if got != 0 {
				t.Errorf("boundedInt32(%q) = %d, want 0 so the caller falls back to its default",
					tt.input, got)
			}
			if got < 0 {
				t.Errorf("boundedInt32(%q) = %d — a negative reached the caller", tt.input, got)
			}
		})
	}
}

// A limit is a promise about how much work a request may cost, so it needs a
// ceiling as well as a floor.
func TestDiagnosticLimitsAreClamped(t *testing.T) {
	tests := []struct {
		name  string
		query string
		max   int32
		want  int32
	}{
		{name: "ordinary limit passes through", query: "25", max: maxPageSize, want: 25},
		{name: "oversized limit clamps", query: "500000", max: maxPageSize, want: maxPageSize},
		{name: "oversized offset clamps", query: "999999999", max: maxPageNumber, want: maxPageNumber},
		{name: "negative is refused", query: "-1", max: maxPageSize, want: 0},
		{name: "absent means unset", query: "", max: maxPageSize, want: 0},
		{name: "junk means unset", query: "50; DROP TABLE", max: maxPageSize, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := boundedInt32(tt.query, tt.max); got != tt.want {
				t.Errorf("boundedInt32(%q, %d) = %d, want %d", tt.query, tt.max, got, tt.want)
			}
		})
	}
}

// The handlers read straight off the query string, so confirm the values they
// would actually see are bounded end to end.
func TestQueryStringLimitsAreBounded(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet,
		"/v1/diag/security-threats?limit=4294967297&offset=2147483648", nil)

	limit := boundedInt32(r.URL.Query().Get("limit"), maxPageSize)
	offset := boundedInt32(r.URL.Query().Get("offset"), maxPageNumber)

	if limit < 0 || offset < 0 {
		t.Errorf("negative pagination reached the caller: limit=%d offset=%d", limit, offset)
	}
	if limit > maxPageSize || offset > maxPageNumber {
		t.Errorf("unbounded pagination reached the caller: limit=%d offset=%d", limit, offset)
	}
}
