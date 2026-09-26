// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ClientAddr takes the entrypoint's answer when there is one, and otherwise
// believes no forwarding header at all -- not even from a Cloudflare address,
// which GetClientIP(r, true) trusted whatever the operator had configured.
func TestClientAddrBelievesOnlyTheEntrypoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "173.245.48.1:40000"
	req.Header.Set(HeaderCloudflareConnectingIP, "127.0.0.1")
	req.Header.Set("X-Forwarded-For", "10.0.0.9")

	if got := ClientAddr(req); got != "173.245.48.1" {
		t.Fatalf("with no entrypoint state ClientAddr = %q, want the peer 173.245.48.1", got)
	}

	resolved := req.WithContext(WithState(req.Context(), &RequestState{ClientRemoteAddr: "203.0.113.7"}))
	if got := ClientAddr(resolved); got != "203.0.113.7" {
		t.Fatalf("with the entrypoint's answer ClientAddr = %q, want 203.0.113.7", got)
	}

	v6 := httptest.NewRequest(http.MethodGet, "/", nil)
	v6.RemoteAddr = "[2001:db8::1]:443"
	if got := ClientAddr(v6); got != "2001:db8::1" {
		t.Fatalf("ClientAddr of a bracketed IPv6 peer = %q, want 2001:db8::1", got)
	}
}
