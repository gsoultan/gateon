// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// An ipfilter entry without a "/" names one address. It was inserted into the
// prefix tree as entry+"/32" whatever its family, which for IPv4 is the host
// and for IPv6 is 2^96 addresses: allow_list "2001:db8::1" admitted all of
// 2001:db8::/32, and deny_list "2001:db8::1" refused all of it. The common
// allow_list "127.0.0.1,::1" admitted every address whose first 32 bits are
// zero.
func TestIPFilterTreatsABareIPv6AddressAsOneHost(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "origin")
	}))
	defer backend.Close()

	cases := []struct {
		name, key, peer string
		want            int
	}{
		{"allow admits the host itself", "allow_list", "[2001:db8::1]:40000", http.StatusOK},
		{"allow refuses a neighbour in the same /32", "allow_list", "[2001:db8:ffff::5]:40000", http.StatusForbidden},
		{"deny refuses the host itself", "deny_list", "[2001:db8::1]:40000", http.StatusForbidden},
		{"deny leaves a neighbour in the same /32 alone", "deny_list", "[2001:db8:ffff::5]:40000", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw := routeIdentityGateway(t, backend.URL,
				&gateonv1.Route{Id: "v6-route", Rule: "PathPrefix(`/`)", Type: "http"},
				&gateonv1.Middleware{Id: "ips", Name: "ips", Type: "ipfilter",
					Config: map[string]string{tc.key: "2001:db8::1"}})
			req := httptest.NewRequest(http.MethodGet, "http://v6.test/", nil)
			req.RemoteAddr = tc.peer
			if got := serveRecorded(gw, req).Code; got != tc.want {
				t.Fatalf("%s=2001:db8::1, peer %s: status %d, want %d", tc.key, tc.peer, got, tc.want)
			}
		})
	}
}
