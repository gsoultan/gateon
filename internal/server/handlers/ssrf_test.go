// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The diagnostics "test this URL" endpoint fetches a target the caller supplies,
// which is SSRF by design and guarded by ssrfSafeTransport. The guard used to
// validate the host with its own LookupIP and then hand the *name* to the
// dialer, which resolved it again — two resolutions, and a low-TTL answer is
// free to differ between them. Its comment claimed to close that window; it did
// not. The dialer's Control hook does, because Go calls it with the literal
// address it is about to connect to.

func TestBlockInternalAddressRejectsInternalTargets(t *testing.T) {
	blocked := []struct{ name, addr string }{
		{name: "IPv4 loopback", addr: "127.0.0.1:80"},
		{name: "IPv4 loopback, alternate", addr: "127.0.0.53:80"},
		{name: "IPv6 loopback", addr: "[::1]:80"},
		{name: "RFC1918 ten", addr: "10.0.0.5:8080"},
		{name: "RFC1918 172.16", addr: "172.16.4.4:80"},
		{name: "RFC1918 192.168", addr: "192.168.1.1:80"},
		{name: "cloud metadata", addr: "169.254.169.254:80"},
		{name: "IPv6 link-local", addr: "[fe80::1]:80"},
		{name: "IPv6 unique local", addr: "[fd00::1]:80"},
		{name: "unspecified v4", addr: "0.0.0.0:80"},
		{name: "unspecified v6", addr: "[::]:80"},
		{name: "multicast", addr: "224.0.0.1:80"},
		// ::ffff:127.0.0.1 is loopback wearing an IPv6 hat; Unmap must see through it.
		{name: "IPv4-mapped loopback", addr: "[::ffff:127.0.0.1]:80"},
		{name: "IPv4-mapped private", addr: "[::ffff:10.0.0.1]:80"},
	}
	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			if err := blockInternalAddress("tcp", tt.addr, nil); err == nil {
				t.Errorf("blockInternalAddress(%q) allowed an internal address", tt.addr)
			}
		})
	}
}

func TestBlockInternalAddressAllowsPublicTargets(t *testing.T) {
	allowed := []string{"93.184.216.34:80", "1.1.1.1:443", "[2606:4700:4700::1111]:443"}
	for _, addr := range allowed {
		if err := blockInternalAddress("tcp", addr, nil); err != nil {
			t.Errorf("blockInternalAddress(%q) refused a public address: %v", addr, err)
		}
	}
}

// Control is handed a literal by the runtime. Anything else means an assumption
// broke, and the safe response is to refuse rather than to pass it through.
func TestBlockInternalAddressRefusesNonLiterals(t *testing.T) {
	for _, addr := range []string{"example.com:80", "not-an-address", "", ":::"} {
		if err := blockInternalAddress("tcp", addr, nil); err == nil {
			t.Errorf("blockInternalAddress(%q) allowed a non-literal address", addr)
		}
	}
}

// The property that matters end to end: a transport built by ssrfSafeTransport
// must refuse to reach a loopback listener, even though that listener is real
// and reachable by any ordinary client.
func TestSSRFSafeTransportCannotReachLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Sanity: the listener really is reachable without the guard, or this test
	// would pass for the wrong reason.
	if resp, err := http.Get(srv.URL); err != nil {
		t.Fatalf("premise check: plain client could not reach the test server: %v", err)
	} else {
		_ = resp.Body.Close()
	}

	client := &http.Client{Transport: ssrfSafeTransport()}
	resp, err := client.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("ssrfSafeTransport reached a loopback address")
	}
	if !strings.Contains(err.Error(), "ssrf blocked") {
		t.Errorf("blocked, but not by the SSRF guard: %v", err)
	}
}

// A hostname that resolves to loopback must also be refused — this is the shape
// a rebinding attack takes, with the name looking innocuous.
func TestSSRFSafeTransportRejectsHostnameResolvingToLoopback(t *testing.T) {
	if _, err := net.DefaultResolver.LookupHost(context.Background(), "localhost"); err != nil {
		t.Skip("no resolver available")
	}
	client := &http.Client{Transport: ssrfSafeTransport()}
	resp, err := client.Get("http://localhost:1/")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("ssrfSafeTransport allowed a hostname resolving to loopback")
	}
	if !strings.Contains(err.Error(), "ssrf blocked") {
		t.Errorf("blocked, but not by the SSRF guard: %v", err)
	}
}
