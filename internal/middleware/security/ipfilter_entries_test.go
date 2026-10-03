// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAMalformedEntryIsRefusedNamingIt: a deny-list entry the filter cannot
// read -- a wildcard, a range, a /33 -- was dropped with a server-side WARN, the
// save answered 200, and the address it was meant to block was served. Now the
// filter is not built, so the save is refused (on every transport: they all
// validate by building) and the message names the entry.
func TestAMalformedEntryIsRefusedNamingIt(t *testing.T) {
	for _, tc := range []struct{ key, list, bad string }{
		{"deny_list", "127.0.0.*", "127.0.0.*"},
		{"deny_list", "10.0.0.1, 127.0.0.0-127.0.0.255", "127.0.0.0-127.0.0.255"},
		{"deny_list", "127.0.0.1/33", "127.0.0.1/33"},
		{"deny_list", "203.0.113.7 198.51.100.2", "203.0.113.7 198.51.100.2"},
		{"allow_list", "10.0.0/8", "10.0.0/8"},
		{"allow_list", "2001:db8::/129", "2001:db8::/129"},
	} {
		_, err := NewIPFilter(map[string]string{tc.key: tc.list})
		if err == nil || !strings.Contains(err.Error(), tc.key) || !strings.Contains(err.Error(), `"`+tc.bad+`"`) {
			t.Errorf("%s %q: err = %v, want a refusal naming %s and the entry %q", tc.key, tc.list, err, tc.key, tc.bad)
		}
	}
}

// TestWellFormedEntriesStillFilter: what is refused is only what could not be
// read; exact addresses and CIDRs of both families still build and still block.
func TestWellFormedEntriesStillFilter(t *testing.T) {
	mw, err := NewIPFilter(map[string]string{
		"deny_list":  "127.0.0.1, 192.0.2.0/24, 2001:db8::1, 2001:db8:1::/48",
		"allow_list": "",
	})
	if err != nil {
		t.Fatalf("well-formed entries refused: %v", err)
	}
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for addr, want := range map[string]int{
		"127.0.0.1:1": http.StatusForbidden, "192.0.2.9:1": http.StatusForbidden,
		"[2001:db8::1]:1": http.StatusForbidden, "[2001:db8:1::5]:1": http.StatusForbidden,
		"198.51.100.1:1": http.StatusOK,
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s: status %d, want %d", addr, rec.Code, want)
		}
	}
}
