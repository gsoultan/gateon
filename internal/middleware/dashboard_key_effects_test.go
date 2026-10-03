// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// keyEffect is one entry of the dashboard-key effect registry (ADR 0048).
//
// A gate that accepts any Go mention of a setting as proof it works passed
// with five inert security switches present (T38): a key read into a struct
// nothing consults, or one the code path consults and the engine ignores. The
// only proof a setting works is to change it and watch the gateway change. So
// each row builds the middleware twice through the factory the router uses --
// once with key=a, once with key=b -- serves the same probe through both, and
// requires the responses to differ.
//
// A row marked inert names the finding that says the key does nothing. It
// asserts the key is STILL inert: when the fix lands the row fails, and the
// fixer turns it into a proof by deleting the mark. scripts/checkconfig reads
// this table and fails when a key the dashboard writes has neither a row here
// nor a line in scripts/checkconfig/effects-baseline.txt.
type keyEffect struct {
	mwType, key string
	base        map[string]string // the rest of the config
	a, b        string            // the two values compared
	probe       func(t *testing.T) *http.Request
	requests    int              // probe this many times (rate limits); 0 = once
	backend     http.HandlerFunc // nil = echoBackend
	inert       string           // the finding that says it does nothing
}

// dashboardKeyEffects is the registry.
var dashboardKeyEffects = []keyEffect{
	{mwType: "waf", key: "sqli", a: "true", b: "false", probe: get("/?id=1%27%20OR%20%271%27%3D%271"),
		inert: "T8: the category switches disable gateon's specs; gwaf's core rules still match (wafgeo, ADR 0044)"},
	{mwType: "waf", key: "xss", a: "true", b: "false", probe: get("/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
		inert: "T8: as sqli"},
	{mwType: "waf", key: "audit_only", a: "false", b: "true", probe: get("/?id=1%27%20OR%20%271%27%3D%271")},
	{mwType: "ipfilter", key: "deny_list", a: "", b: "198.51.100.9", probe: getFrom("/", "198.51.100.9:4000")},
	{mwType: "ipfilter", key: "allow_list", a: "", b: "203.0.113.1", probe: getFrom("/", "198.51.100.9:4000")},
	{mwType: "xfcc", key: "forward_subject", a: "false", b: "true", probe: withClientCert},
	{mwType: "xfcc", key: "forward_by", base: map[string]string{"forward_subject": "true"}, a: "false", b: "true",
		probe: withClientCert, inert: "T21: read into XFCCConfig.ForwardBy and never used (authmw, ADR 0046)"},
	{mwType: "compress", key: "max_buffer_bytes", a: "8192", b: "4096", probe: gzipGet, backend: sizedBody(5000)},
	{mwType: "ratelimit", key: "burst", a: "5", b: "1", probe: getFrom("/", "198.51.100.20:4000"), requests: 3},
	{mwType: "cors", key: "allowed_origins", a: "https://a.example", b: "https://b.example", probe: fromOrigin("https://b.example")},
	{mwType: "buffering", key: "max_request_body_bytes", a: "1048576", b: "10", probe: postBody(100)},
}

func TestDashboardKeysChangeWhatTheGatewayDoes(t *testing.T) {
	for _, row := range dashboardKeyEffects {
		t.Run(row.mwType+"/"+row.key, func(t *testing.T) {
			withA, withB := observe(t, row, row.a), observe(t, row, row.b)
			switch differs := withA != withB; {
			case row.inert == "" && !differs:
				t.Errorf("%s=%q and %s=%q answer the same probe identically:\n  %s\nthe setting has no effect",
					row.key, row.a, row.key, row.b, withA)
			case row.inert != "" && differs:
				t.Errorf("%s now has an effect (%q -> %s, %q -> %s); delete its inert mark (%s)",
					row.key, row.a, withA, row.b, withB, row.inert)
			}
		})
	}
}

// observe builds the middleware with key=value through the factory and
// records what the probe gets back, and what reached the backend.
func observe(t *testing.T, row keyEffect, value string) string {
	t.Helper()
	cfg := maps.Clone(row.base)
	if cfg == nil {
		cfg = map[string]string{}
	}
	cfg[row.key] = value
	mw, err := NewFactory(nil, nil, nil, nil, t.TempDir()).Create(
		&gateonv1.Middleware{Id: "effect", Type: row.mwType, Config: cfg}, "effect-route")
	if err != nil {
		t.Fatalf("build %s with %s=%q: %v", row.mwType, row.key, value, err)
	}
	backend := row.backend
	if backend == nil {
		backend = echoBackend
	}
	h := mw(backend)
	var out []string
	for range max(row.requests, 1) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, row.probe(t))
		out = append(out, fmt.Sprintf("%d enc=%q acao=%q body=%q", rec.Code,
			rec.Header().Get("Content-Encoding"), rec.Header().Get("Access-Control-Allow-Origin"), rec.Body.String()))
	}
	return strings.Join(out, " | ")
}

// echoBackend answers with the client-certificate header it was given.
func echoBackend(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	_, _ = io.WriteString(w, "xfcc="+r.Header.Get("X-Forwarded-Client-Cert"))
}

func sizedBody(n int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		_, _ = w.Write([]byte(strings.Repeat("a", n)))
	}
}

func get(target string) func(*testing.T) *http.Request {
	return getFrom(target, "198.51.100.10:4000")
}

func getFrom(target, remote string) func(*testing.T) *http.Request {
	return func(*testing.T) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://app.example"+target, nil)
		r.RemoteAddr = remote
		return r
	}
}

func gzipGet(t *testing.T) *http.Request {
	r := get("/")(t)
	r.Header.Set("Accept-Encoding", "gzip")
	return r
}

func fromOrigin(origin string) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		r := get("/")(t)
		r.Header.Set("Origin", origin)
		return r
	}
}

func postBody(n int) func(*testing.T) *http.Request {
	return func(*testing.T) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://app.example/", strings.NewReader(strings.Repeat("x", n)))
		r.RemoteAddr = "198.51.100.10:4000"
		return r
	}
}

// withClientCert is a request over TLS that presented a client certificate.
func withClientCert(t *testing.T) *http.Request {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"client.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	r := get("/")(t)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r
}
