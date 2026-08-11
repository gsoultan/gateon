// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Pagination values come straight off the query string. The original code did
// strconv.Atoi followed by int32(), which on a 64-bit build parses "4294967297"
// successfully as an int and then truncates it to 1 — so a caller could select a
// page by overflowing into it, and "-5" passed through as a negative page. A
// large page size was separately unbounded, turning one request into one very
// large query.
//
// Against the pre-fix code the overflow and negative cases below return 1 and -5
// instead of 0, and the huge-page-size case returns 10000000 instead of the cap.

func TestBoundedInt32RejectsOverflowAndNegatives(t *testing.T) {
	tests := []struct {
		name  string
		input string
		max   int32
		want  int32
	}{
		{name: "empty is unset", input: "", max: 100, want: 0},
		{name: "ordinary value", input: "7", max: 100, want: 7},
		{name: "at the ceiling", input: "100", max: 100, want: 100},
		{name: "above the ceiling clamps", input: "10000000", max: 100, want: 100},
		{name: "negative is rejected", input: "-5", max: 100, want: 0},
		// 2^32+1. Atoi parses this fine on 64-bit and int32() truncates it to 1.
		{name: "int32 overflow does not wrap", input: "4294967297", max: 1000, want: 0},
		// One past MaxInt32.
		{name: "just past MaxInt32", input: "2147483648", max: 1000, want: 0},
		{name: "not a number", input: "12abc", max: 100, want: 0},
		{name: "empty-ish junk", input: "   ", max: 100, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := boundedInt32(tt.input, tt.max); got != tt.want {
				t.Errorf("boundedInt32(%q, %d) = %d, want %d", tt.input, tt.max, got, tt.want)
			}
		})
	}
}

func TestParsePaginationBoundsQueryInput(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		wantPage     int32
		wantPageSize int32
	}{
		{name: "normal", query: "?page=2&pageSize=50", wantPage: 2, wantPageSize: 50},
		{name: "snake_case page_size still works", query: "?page_size=25", wantPageSize: 25},
		{
			name:         "oversized page size is capped, not honored",
			query:        "?pageSize=999999",
			wantPageSize: maxPageSize,
		},
		{
			name:     "oversized page is capped",
			query:    "?page=999999999",
			wantPage: maxPageNumber,
		},
		{
			name:         "overflow does not wrap into a valid page",
			query:        "?page=4294967297&pageSize=4294967297",
			wantPage:     0,
			wantPageSize: 0,
		},
		{
			name:         "negatives are rejected",
			query:        "?page=-1&pageSize=-1",
			wantPage:     0,
			wantPageSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/things"+tt.query, nil)
			page, pageSize, _ := ParsePagination(r)

			if page != tt.wantPage {
				t.Errorf("page = %d, want %d", page, tt.wantPage)
			}
			if pageSize != tt.wantPageSize {
				t.Errorf("pageSize = %d, want %d", pageSize, tt.wantPageSize)
			}
			if pageSize < 0 || page < 0 {
				t.Errorf("negative pagination reached the caller: page=%d pageSize=%d", page, pageSize)
			}
		})
	}
}
