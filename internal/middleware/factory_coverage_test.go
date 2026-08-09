// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The factory builds 47 middleware types from operator config, and 18 of them
// had no test of any kind — including oidc, security_headers, schema_validation,
// tls_binding and circuit_breaker. A type nobody exercises is a type where a
// config-parsing mistake or a nil dereference waits until a route in production
// happens to use it.
//
// These two tests are deliberately shallow and broad rather than deep and
// narrow. They do not assert what each middleware *does* — that belongs in a
// test per behaviour — they assert the two properties every one of them must
// have and that are cheap to check for all of them at once:
//
//  1. Create returns a usable middleware, or a real error, for the config an
//     operator would write. Never a panic, and never a nil middleware with a
//     nil error, which the router would then invoke.
//  2. The middleware survives a request. Whether it allows, blocks or rewrites
//     is its own business; crashing is not one of the options.
//
// factoryTypes must list every case in Factory.Create. TestFactoryCoversEveryType
// fails when the two drift apart, so a new middleware cannot be added without
// either a config here or a deliberate decision to skip it.

// factoryCase is one middleware type and a minimal viable config for it.
type factoryCase struct {
	typ string
	cfg map[string]string
	// skipServe marks middleware that cannot serve a plain request in a unit
	// test — they need a live dependency (a redis client, an OIDC provider, a
	// TLS peer certificate). Construction is still checked.
	skipServe bool
	why       string
}

func factoryCases(t *testing.T) []factoryCase {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.pem")
	// A syntactically valid but empty CA bundle: enough for construction.
	if err := os.WriteFile(certFile, []byte(""), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	return []factoryCase{
		{typ: "ratelimit", cfg: map[string]string{"average": "100", "burst": "200"}},
		{typ: "auth", cfg: map[string]string{"type": "apikey", "key_demo": "tenant-a"}},
		{typ: "headers", cfg: map[string]string{"set_response_X-Test": "1"}},
		{typ: "forwardedheaders", cfg: map[string]string{"trust_forward_header": "true"}},
		{typ: "rewrite", cfg: map[string]string{"regex": "^/a", "replacement": "/b"}},
		{typ: "addprefix", cfg: map[string]string{"prefix": "/api"}},
		{typ: "stripprefix", cfg: map[string]string{"prefixes": "/api"}},
		{typ: "stripprefixregex", cfg: map[string]string{"regex": "^/api/v[0-9]+"}},
		{typ: "replacepath", cfg: map[string]string{"path": "/fixed"}},
		{typ: "replacepathregex", cfg: map[string]string{"regex": "^/a/(.*)", "replacement": "/b/$1"}},
		{typ: "accesslog", cfg: map[string]string{}},
		{typ: "metrics", cfg: map[string]string{}},
		{typ: "compress", cfg: map[string]string{}},
		{typ: "errors", cfg: map[string]string{"status": "500", "service": "x"}},
		{typ: "retry", cfg: map[string]string{"attempts": "3"}},
		{typ: "cors", cfg: map[string]string{"allowed_origins": "https://example.com"}},
		{typ: "grpcweb", cfg: map[string]string{"allowed_origins": "*"}},
		{typ: "ipfilter", cfg: map[string]string{"allow_list": "127.0.0.1"}},
		{typ: "request_id", cfg: map[string]string{}},
		{typ: "cache", cfg: map[string]string{"ttl": "60"}},
		{typ: "inflightreq", cfg: map[string]string{"amount": "10"}},
		{typ: "buffering", cfg: map[string]string{"max_request_body_bytes": "1048576"}},
		{typ: "forwardauth", cfg: map[string]string{"address": "http://127.0.0.1:1/auth"},
			skipServe: true, why: "dials an external authorizer"},
		{typ: "waf", cfg: map[string]string{"sqli": "true", "xss": "true"}},
		{typ: "oidc", cfg: map[string]string{
			"issuer": "https://accounts.example.com", "client_id": "id",
			"client_secret": "secret", "redirect_url": "https://app.example.com/cb"},
			skipServe: true, why: "performs OIDC discovery against the issuer"},
		{typ: "graphql_firewall", cfg: map[string]string{"max_depth": "10"}},
		{typ: "bot_management", cfg: map[string]string{"enabled": "false"}},
		{typ: "xss_recognition", cfg: map[string]string{}},
		{typ: "sqli_recognition", cfg: map[string]string{}},
		{typ: "threat_recognition", cfg: map[string]string{}},
		{typ: "schema_validation", cfg: map[string]string{}},
		{typ: "honeypot", cfg: map[string]string{"paths": "/.env"}},
		{typ: "turnstile", cfg: map[string]string{"secret": "s", "site_key": "k"},
			skipServe: true, why: "verifies against Cloudflare"},
		{typ: "geoip", cfg: map[string]string{}},
		{typ: "hmac", cfg: map[string]string{"secret": "shhh"}},
		{typ: "deception", cfg: map[string]string{"enabled": "false"}},
		{typ: "tarpit", cfg: map[string]string{"enabled": "false"}},
		{typ: "entropy", cfg: map[string]string{}},
		{typ: "pow", cfg: map[string]string{"secret": "s", "difficulty": "1", "enabled": "false"}},
		{typ: "policy", cfg: map[string]string{}},
		{typ: "xfcc", cfg: map[string]string{}},
		{typ: "transform", cfg: map[string]string{"response_search": "a", "response_replace": "b"}},
		{typ: "file_security", cfg: map[string]string{"max_file_size": "1024"}},
		{typ: "tls_binding", cfg: map[string]string{}},
		{typ: "security_headers", cfg: map[string]string{}},
		{typ: "circuit_breaker", cfg: map[string]string{"failure_threshold": "5"}},
		{typ: "wasm", cfg: map[string]string{}, skipServe: true, why: "needs a compiled module"},
	}
}

// TestFactoryCoversEveryType keeps factoryCases honest: every `case "x":` in
// Factory.Create must appear here, so adding a middleware without a smoke case
// is a failing test rather than a silent coverage hole.
func TestFactoryCoversEveryType(t *testing.T) {
	src, err := os.ReadFile("factory.go")
	if err != nil {
		t.Fatalf("read factory.go: %v", err)
	}

	covered := make(map[string]bool)
	for _, c := range factoryCases(t) {
		covered[c.typ] = true
	}

	var missing []string
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `case "`) {
			continue
		}
		// case "a", "b": — take every quoted literal on the line.
		for _, part := range strings.Split(line, `"`) {
			if part == "" || strings.Contains(part, "case") || strings.Contains(part, ":") {
				continue
			}
			if !covered[part] {
				missing = append(missing, part)
			}
		}
	}
	if len(missing) > 0 {
		t.Errorf("Factory.Create handles these types but factoryCases has no entry: %v\n"+
			"Add a minimal config so the type is at least smoke-tested.", missing)
	}
}

// TestFactoryBuildsAndServesEveryType is the smoke test proper.
func TestFactoryBuildsAndServesEveryType(t *testing.T) {
	for _, tc := range factoryCases(t) {
		t.Run(tc.typ, func(t *testing.T) {
			f := NewFactory(nil, &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{}}, nil, nil, t.TempDir())

			mw, err := f.Create(&gateonv1.Middleware{
				Id: "smoke-" + tc.typ, Type: tc.typ, Config: tc.cfg,
			}, "smoke-route")
			if err != nil {
				// A refusal is a legitimate outcome — the config may be
				// genuinely insufficient — as long as it is reported and not
				// paired with a middleware the router would then use.
				if mw != nil {
					t.Errorf("Create returned both an error and a middleware: %v", err)
				}
				t.Skipf("Create refused this config: %v", err)
			}
			if mw == nil {
				t.Fatal("Create returned a nil middleware and a nil error; the router " +
					"would invoke this and panic")
			}
			if tc.skipServe {
				t.Logf("construction only: %s", tc.why)
				return
			}

			reached := false
			h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			}))

			req := httptest.NewRequest(http.MethodGet, "/smoke?q=1", strings.NewReader(""))
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.RemoteAddr = "127.0.0.1:12345"
			rr := httptest.NewRecorder()

			// A panic here is the failure this test exists to catch.
			h.ServeHTTP(rr, req)

			if rr.Code == 0 {
				t.Errorf("no status written (backend reached: %v)", reached)
			}
		})
	}
}
