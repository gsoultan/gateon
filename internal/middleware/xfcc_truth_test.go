// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The XFCC middleware (ADR 0046) wrote certificate fields into
// X-Forwarded-Client-Cert unescaped, so a client certificate whose URI SAN
// contained ";Hash=..." added a Hash element of the client's choosing, and its
// "Forward By" switch was read and never used.

// xfccElement is one parsed XFCC element: each key's values in order.
type xfccElement map[string][]string

// parseXFCC reads an X-Forwarded-Client-Cert value the way Envoy defines it:
// elements separated by ',', pairs by ';', a value optionally double-quoted,
// inside which a backslash escapes the next character ('\"' is a quote, '\\'
// a backslash). Separators inside quotes are text.
func parseXFCC(t *testing.T, v string) []xfccElement {
	t.Helper()
	var (
		out     []xfccElement
		cur     = xfccElement{}
		pair    strings.Builder
		inQuote bool
	)
	flushPair := func() {
		key, val, ok := strings.Cut(pair.String(), "=")
		if !ok {
			t.Fatalf("XFCC %q: pair %q has no '='", v, pair.String())
		}
		cur[key] = append(cur[key], val)
		pair.Reset()
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case inQuote && c == '\\' && i+1 < len(v):
			pair.WriteByte(v[i+1])
			i++
		case c == '"':
			inQuote = !inQuote
		case !inQuote && c == ';':
			flushPair()
		case !inQuote && c == ',':
			flushPair()
			out = append(out, cur)
			cur = xfccElement{}
		default:
			pair.WriteByte(c)
		}
	}
	if inQuote {
		t.Fatalf("XFCC %q: unterminated quote", v)
	}
	flushPair()
	return append(out, cur)
}

// xfccSeenBy builds an xfcc middleware through the factory and returns the
// X-Forwarded-Client-Cert the backend received for a request over TLS
// presenting cert.
func xfccSeenBy(t *testing.T, cfg map[string]string, cert tls.Certificate) string {
	t.Helper()
	mw, err := NewFactory(nil, nil, nil, nil, t.TempDir()).
		Create(&gateonv1.Middleware{Id: "xfcc-under-test", Type: "xfcc", Config: cfg}, "route-under-test")
	if err != nil {
		t.Fatalf("build xfcc: %v", err)
	}
	seen := make(chan string, 1)
	srv := mtlsServer(t, mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("X-Forwarded-Client-Cert")
	})))
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-Client-Cert", "Hash=client-supplied")
	resp, err := mtlsClient(t, srv, &cert).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return <-seen
}

var xfccAll = map[string]string{
	"forward_hash": "true", "forward_subject": "true", "forward_uri": "true", "forward_dns": "true",
}

// TestXFCCCertificateFieldsCannotInjectElements presents a certificate whose
// URI SAN, DNS SAN and subject carry XFCC separators. Each must arrive as the
// one value it is, inside one element with one Hash.
func TestXFCCCertificateFieldsCannotInjectElements(t *testing.T) {
	const (
		uri = "spiffe://rv/alice;Hash=deadbeef"
		cn  = `alice",URI=spiffe://evil;DNS=x`
	)
	cert := newClientCert(t, clientCertSpec{commonName: cn, uris: []string{uri}, dnsNames: []string{"client.example"}})
	got := xfccSeenBy(t, xfccAll, cert)

	elems := parseXFCC(t, got)
	if len(elems) != 1 {
		t.Fatalf("XFCC %q parses as %d elements, want 1: a certificate field added an element", got, len(elems))
	}
	e := elems[0]
	if len(e["Hash"]) != 1 || e["Hash"][0] == "deadbeef" {
		t.Errorf("XFCC %q: Hash = %v, want exactly the gateway's one: the URI SAN injected a Hash", got, e["Hash"])
	}
	if len(e["URI"]) != 1 || e["URI"][0] != uri {
		t.Errorf("XFCC %q: URI = %v, want [%s]", got, e["URI"], uri)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if want := leaf.Subject.String(); len(e["Subject"]) != 1 || e["Subject"][0] != want {
		t.Errorf("XFCC %q: Subject = %v, want [%s] (the subject DN, RFC 2253)", got, e["Subject"], want)
	}
	if len(e["DNS"]) != 1 || e["DNS"][0] != "client.example" {
		t.Errorf("XFCC %q: DNS = %v, want [client.example]", got, e["DNS"])
	}
}

// TestXFCCForwardByNamesTheGateway turns "Forward By" on: the element must
// carry By, the identity the operator configured for this gateway, first.
func TestXFCCForwardByNamesTheGateway(t *testing.T) {
	cert := newClientCert(t, clientCertSpec{commonName: "alice", uris: []string{"spiffe://rv/alice"}})
	cfg := map[string]string{"forward_by": "true", "by": "spiffe://rv/gateon", "forward_uri": "true"}
	got := xfccSeenBy(t, cfg, cert)

	e := parseXFCC(t, got)[0]
	if len(e["By"]) != 1 || e["By"][0] != "spiffe://rv/gateon" {
		t.Fatalf("XFCC %q: By = %v, want [spiffe://rv/gateon]: Forward By did nothing", got, e["By"])
	}
	if !strings.HasPrefix(got, "By=") {
		t.Errorf("XFCC %q: By is not the first pair, as Envoy orders it", got)
	}
}

// TestXFCCForwardByWithoutAnIdentityIsRefusedAtSave saves Forward By with no
// identity to forward. There is nothing it could name, so the save says so.
func TestXFCCForwardByWithoutAnIdentityIsRefusedAtSave(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	for _, by := range []string{"", "not a uri", "/relative"} {
		err := f.Validate(&gateonv1.Middleware{Id: "x", Type: "xfcc", Config: map[string]string{"forward_by": "true", "by": by}})
		if err == nil {
			t.Errorf("forward_by=true with by=%q saved; the switch would forward nothing", by)
		}
	}
	if err := f.Validate(&gateonv1.Middleware{Id: "x", Type: "xfcc", Config: map[string]string{"forward_by": "false"}}); err != nil {
		t.Errorf("forward_by=false refused: %v", err)
	}
}
