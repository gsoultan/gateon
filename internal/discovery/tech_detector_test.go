// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package discovery

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestBlockedProbeTargetPolicy pins which addresses the probe refuses.
//
// Each blocked row is an address the old URL-based guard let through. Each
// allowed row is a real use of this feature -- probing your own backend, which
// is almost always on a private network -- and blocking those would make the
// feature useless rather than safe.
func TestBlockedProbeTargetPolicy(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
		why     string
	}{
		{"127.0.0.1", true, "loopback, the address the old check compared against"},
		{"127.0.0.2", true, "also loopback; the old check tested equality with 127.0.0.1"},
		{"127.255.255.254", true, "the far end of 127.0.0.0/8"},
		{"::1", true, "IPv6 loopback"},
		{"::ffff:127.0.0.1", true, "IPv4-mapped loopback"},
		{"169.254.169.254", true, "EC2 instance metadata; hands out IAM credentials"},
		{"169.254.0.1", true, "link-local generally"},
		{"fe80::1", true, "IPv6 link-local"},
		{"0.0.0.0", true, "unspecified, routes to this host"},
		{"::", true, "IPv6 unspecified"},
		{"224.0.0.1", true, "link-local multicast"},

		{"10.0.0.5", false, "a backend in a VPC -- the point of the feature"},
		{"192.168.1.10", false, "a NAS on the LAN"},
		{"172.16.4.1", false, "RFC1918"},
		{"93.184.216.34", false, "an ordinary public address"},
		{"2606:2800:220:1:248:1893:25c8:1946", false, "an ordinary public IPv6 address"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("test bug: %q is not an IP", tt.ip)
			}
			reason, blocked := blockedProbeTarget(ip)
			if blocked != tt.blocked {
				t.Errorf("blockedProbeTarget(%s) = %v (%q), want %v -- %s",
					tt.ip, blocked, reason, tt.blocked, tt.why)
			}
			if blocked && reason == "" {
				t.Error("blocked with no reason; the reason reaches the operator in the error")
			}
		})
	}
}

// TestUnparseableAddressIsBlocked keeps the default from being "allow". If the
// address cannot be read, the answer to "is this safe" is not yes.
func TestUnparseableAddressIsBlocked(t *testing.T) {
	if _, blocked := blockedProbeTarget(nil); !blocked {
		t.Error("a nil IP was allowed; an unreadable address must not be treated as safe")
	}
}

// TestDiscoverRefusesLoopback is the regression test for the SSRF bypasses.
//
// Every URL here reached the network under the old guard. The first two are the
// interesting ones: the guard parsed the host by splitting the URL on "/", so
// both produced a "host" that does not resolve, and a failed resolve skipped
// the check entirely rather than failing closed.
func TestDiscoverRefusesLoopback(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("this response must never be read"))
	}))
	defer backend.Close()

	host := strings.TrimPrefix(backend.URL, "http://")
	tests := []struct {
		name string
		url  string
	}{
		{"plain loopback", backend.URL},
		{"userinfo hides the host from a string check", "http://evil.example.com@" + host},
		{"no scheme, defaulted to http", host},
	}

	d := &TechDetector{} // production policy
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := d.Discover(context.Background(), tt.url, nil)
			if err == nil {
				t.Fatalf("Discover(%q) succeeded and returned %+v; it reached loopback", tt.url, resp)
			}
			if !strings.Contains(err.Error(), "refusing to probe") {
				t.Errorf("error = %v, want it to name the refusal", err)
			}
		})
	}
}

// TestDiscoverRefusesRedirectToBlockedAddress covers the hole a URL-level check
// cannot close: the first address is fine and the second is not. The dialer sees
// both because it runs per connection.
func TestDiscoverRefusesRedirectToBlockedAddress(t *testing.T) {
	loopback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("must never be read"))
	}))
	defer loopback.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, loopback.URL, http.StatusFound)
	}))
	defer redirector.Close()

	// The redirector is itself on loopback, so allow the first hop by address
	// and refuse the second, which is what a public host redirecting inward
	// would look like.
	// Atomic because the hook runs on whichever goroutine the transport dials
	// from; the redirect happens to be serial today, and relying on that would
	// make this test a race waiting for a transport change.
	var firstHopUsed atomic.Bool
	d := &TechDetector{blockedTarget: func(ip net.IP) (string, bool) {
		if firstHopUsed.CompareAndSwap(false, true) {
			return "", false
		}
		return blockedProbeTarget(ip)
	}}

	if _, err := d.Discover(context.Background(), redirector.URL, nil); err == nil {
		t.Fatal("a redirect into loopback was followed")
	}
}

// allowAll lets a test probe an httptest server, which always binds loopback.
// It replaces GATEON_TEST=1, which switched the check off for the whole process.
func allowAll(net.IP) (string, bool) { return "", false }

func TestDiscoverIdentifiesTech(t *testing.T) {
	tests := []struct {
		name     string
		handler  http.HandlerFunc
		wantTech string
		wantRecs int
	}{
		{
			name:     "plain http server is generic",
			handler:  func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("hello")) },
			wantTech: "generic_http",
			wantRecs: 0,
		},
		{
			name: "pgadmin by body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte("<title>pgAdmin 4</title>"))
			},
			wantTech: "pgadmin4",
			wantRecs: 2,
		},
		{
			name: "pgadmin by header",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-pgadmin-version", "8.1")
				w.Write([]byte("nothing telling in the body"))
			},
			wantTech: "pgadmin4",
			wantRecs: 2,
		},
		{
			name: "grpc by content type",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/grpc")
			},
			wantTech: "grpc",
			wantRecs: 1,
		},
		{
			name: "go by powered-by header",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Powered-By", "Go")
				w.Write([]byte("ok"))
			},
			wantTech: "golang",
			wantRecs: 1,
		},
		{
			name: "synology by body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte("SYNO.SDS.Direct bootstrap"))
			},
			wantTech: "synology_dsm",
			wantRecs: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			d := &TechDetector{blockedTarget: allowAll}
			res, err := d.Discover(context.Background(), srv.URL, nil)
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			if res.Tech != tt.wantTech {
				t.Errorf("Tech = %q, want %q", res.Tech, tt.wantTech)
			}
			if len(res.Recommendations) != tt.wantRecs {
				t.Errorf("got %d recommendations, want %d", len(res.Recommendations), tt.wantRecs)
			}
			if res.DetectedInfo["status"] == "" {
				t.Error("DetectedInfo lost the status code")
			}
		})
	}
}

// TestDiscoverReportsHeadersItSaw pins the informational fields, which are what
// an operator reads when the tech comes back generic.
func TestDiscoverReportsHeadersItSaw(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	d := &TechDetector{blockedTarget: allowAll}
	res, err := d.Discover(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if got := res.DetectedInfo["status"]; got != "418" {
		t.Errorf("status = %q, want \"418\"", got)
	}
	if got := res.DetectedInfo["server"]; got != "nginx/1.25.3" {
		t.Errorf("server = %q, want the Server header", got)
	}
}

// TestDiscoverFailsWhenTheTargetIsUnreachable checks the probe reports a dead
// backend rather than inventing a verdict about it.
func TestDiscoverFailsWhenTheTargetIsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	d := &TechDetector{blockedTarget: allowAll}
	if _, err := d.Discover(context.Background(), url, nil); err == nil {
		t.Fatal("Discover succeeded against a closed port")
	}
}

// TestDiscoverAcceptsAHostWithoutAScheme covers the http:// prefixing, which is
// also how a bare "host:port" from the dashboard arrives.
func TestDiscoverAcceptsAHostWithoutAScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := &TechDetector{blockedTarget: allowAll}
	res, err := d.Discover(context.Background(), strings.TrimPrefix(srv.URL, "http://"), nil)
	if err != nil {
		t.Fatalf("Discover without a scheme: %v", err)
	}
	if res.Tech != "generic_http" {
		t.Errorf("Tech = %q, want generic_http", res.Tech)
	}
}
