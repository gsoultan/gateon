// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

// The HTTP->HTTPS redirect sends the client back to the name it asked for, so
// the target is built from the request. gosec flags that as an open redirect
// and is right to look: the reason it is safe is that a victim's browser sends
// the origin it is visiting, not that the value is validated here.
//
// These pin the request shapes that make the target something other than the
// Host header, because the guarantee rests on the client's request shape and
// nothing in this function enforces it.

func requestFromWire(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("net/http rejected the request line: %v", err)
	}
	return req
}

func TestRedirectTargetForAnOrdinaryRequest(t *testing.T) {
	r := requestFromWire(t, "GET /path?a=b HTTP/1.1\r\nHost: gateway.example.com\r\n\r\n")
	if got, want := redirectTargetURL(r, "443"), "https://gateway.example.com/path?a=b"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// An opaque request target used to be concatenated onto the host rather than
// appended as a path: "GET http:evil.com" produced
// https://gateway.example.comevil.com, and the registrable domain of that is
// comevil.com, which an attacker can register. Building the path from
// EscapedPath keeps the host intact whatever the target looks like.
func TestRedirectTargetCannotExtendTheHost(t *testing.T) {
	r := requestFromWire(t, "GET http:evil.com HTTP/1.1\r\nHost: gateway.example.com\r\n\r\n")
	got := redirectTargetURL(r, "443")

	if strings.HasPrefix(got, "https://gateway.example.comevil.com") {
		t.Fatalf("the request target extended the host: %q", got)
	}
	if !strings.HasPrefix(got, "https://gateway.example.com/") {
		t.Fatalf("got %q, want a URL on gateway.example.com", got)
	}
}

// A protocol-relative-looking path must stay a path on this host, not become
// another origin.
func TestRedirectTargetKeepsDoubleSlashPathsOnThisHost(t *testing.T) {
	r := requestFromWire(t, "GET //evil.com/p HTTP/1.1\r\nHost: gateway.example.com\r\n\r\n")
	if got, want := redirectTargetURL(r, "443"), "https://gateway.example.com//evil.com/p"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Absolute-form: net/http sets r.Host from the request target rather than the
// Host header (RFC 7230), so the redirect follows the target. Recorded rather
// than prevented -- no browser emits absolute-form to an origin server, so a
// caller can only redirect itself, and refusing it would break a forward-proxy
// shape if gateon ever grows one. If that assumption changes, this test is
// where it is written down.
func TestRedirectTargetFollowsAbsoluteFormHost(t *testing.T) {
	r := requestFromWire(t, "GET http://evil.com/p HTTP/1.1\r\nHost: gateway.example.com\r\n\r\n")
	if got, want := redirectTargetURL(r, "443"), "https://evil.com/p"; got != want {
		t.Fatalf("got %q, want %q -- if this changed, the comment on redirectTargetURL needs updating too", got, want)
	}
}

func TestRedirectTargetDropsThePlaintextPortAndAddsTheTLSOne(t *testing.T) {
	r := requestFromWire(t, "GET /x HTTP/1.1\r\nHost: gateway.example.com:8080\r\n\r\n")
	if got, want := redirectTargetURL(r, "8443"), "https://gateway.example.com:8443/x"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
