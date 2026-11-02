// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"maps"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gsoultan/gateon/internal/middleware/auth"
	"github.com/gsoultan/gateon/internal/request"
)

// mirrorBackend answers with what reached it: the method, the path, the query,
// the forwarded scheme and the body. A row whose effect is on the request
// (a rewrite, a header the gateway sets) is seen here.
func mirrorBackend(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	_, _ = io.WriteString(w, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery+
		" scheme="+request.Scheme(r)+" body="+string(body))
}

// textBackend answers 200 with body as text/plain.
func textBackend(body, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", contentType)
		_, _ = io.WriteString(w, body)
	}
}

// chunkedBackend writes its body in the pieces given, one Write each.
func chunkedBackend(pieces ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for _, p := range pieces {
			_, _ = io.WriteString(w, p)
		}
	}
}

// statusBackend answers every request with code.
func statusBackend(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, "from-backend")
	}
}

// failingFirst fails the first n requests it is sent, then succeeds.
func failingFirst(n int64) func() http.HandlerFunc {
	return func() http.HandlerFunc {
		var seen atomic.Int64
		return func(w http.ResponseWriter, _ *http.Request) {
			if seen.Add(1) <= n {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			_, _ = io.WriteString(w, "ok")
		}
	}
}

// countingBackend answers with how many requests it has served, so a response
// served from a cache is told apart from one the backend produced.
func countingBackend() http.HandlerFunc {
	var n atomic.Int64
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, "served="+strings.Repeat("x", 2048)+string(rune('0'+n.Add(1))))
	}
}

func withHeader(base func(*testing.T) *http.Request, name, value string) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		r := base(t)
		r.Header.Set(name, value)
		return r
	}
}

func preflight(origin, method, headers string) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		r := newProbe(http.MethodOptions, "/", "")
		r.Header.Set("Origin", origin)
		r.Header.Set("Access-Control-Request-Method", method)
		if headers != "" {
			r.Header.Set("Access-Control-Request-Headers", headers)
		}
		return r
	}
}

func newProbe(method, target, body string) *http.Request {
	r, _ := http.NewRequest(method, "http://app.example"+target, strings.NewReader(body))
	r.RemoteAddr = "198.51.100.10:4000"
	r.RequestURI = target
	return r
}

// originGet is a GET in origin form ("GET /path"), as a browser sends it.
// get's absolute form puts the whole URL in the request target, which a rule
// on absolute URLs in request values reads as one.
func originGet(target string) func(*testing.T) *http.Request {
	return func(*testing.T) *http.Request { return newProbe(http.MethodGet, target, "") }
}

// signedPost is a POST of body signed with secret, as a webhook sender signs.
func signedPost(secret, header, prefix, body string) func(*testing.T) *http.Request {
	return func(*testing.T) *http.Request {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(body))
		r := newProbe(http.MethodPost, "/hook", body)
		r.Header.Set(header, prefix+hex.EncodeToString(mac.Sum(nil)))
		return r
	}
}

// moreKeyEffects extends the registry with the keys effects-baseline.txt
// listed as unproven. Each is a row of the same table, through the same
// factory.
var moreKeyEffects = []keyEffect{
	// Paths.
	{mwType: "addprefix", key: "prefix", a: "/a", b: "/b", probe: get("/x"), backend: mirrorBackend},
	{mwType: "stripprefix", key: "prefixes", a: "/api", b: "/v1", probe: get("/v1/x"), backend: mirrorBackend},
	// The REST and gRPC APIs take the list as written; a space after a comma
	// made the second prefix one no path starts with.
	{mwType: "stripprefix", key: "prefixes", a: "/api", b: "/api, /v1", probe: get("/v1/x"), backend: mirrorBackend},
	{mwType: "stripprefixregex", key: "regex", a: "^/api", b: "^/v[0-9]+", probe: get("/v1/x"), backend: mirrorBackend},
	{mwType: "replacepath", key: "path", a: "/a", b: "/b", probe: get("/x"), backend: mirrorBackend},
	{mwType: "replacepathregex", key: "pattern", base: map[string]string{"replacement": "/new"},
		a: "^/zzz", b: "^/old", probe: get("/old/x"), backend: mirrorBackend},
	{mwType: "replacepathregex", key: "replacement", base: map[string]string{"pattern": "^/old(.*)"},
		a: "/a$1", b: "/b$1", probe: get("/old/x"), backend: mirrorBackend},
	{mwType: "rewrite", key: "path", a: "/a", b: "/b", probe: get("/x"), backend: mirrorBackend},
	{mwType: "rewrite", key: "pattern", base: map[string]string{"replacement": "/new"},
		a: "^/zzz", b: "^/old", probe: get("/old/x"), backend: mirrorBackend},
	{mwType: "rewrite", key: "replacement", base: map[string]string{"pattern": "^/old(.*)"},
		a: "/a$1", b: "/b$1", probe: get("/old/x"), backend: mirrorBackend},

	// Forwarded headers.
	{mwType: "forwardedheaders", key: "proto", a: "http", b: "https", probe: get("/"), backend: mirrorBackend},
	{mwType: "forwardedheaders", key: "trust_forward_header", a: "false", b: "true",
		probe: withHeader(get("/"), "X-Forwarded-Proto", "https"), backend: mirrorBackend},

	// Errors and retries.
	{mwType: "errors", key: "status_codes", base: map[string]string{"page_404": "gone", "page_500": "broken"},
		a: "500", b: "404", probe: get("/"), backend: statusBackend(http.StatusNotFound)},
	{mwType: "retry", key: "attempts", a: "0", b: "3", probe: get("/"), freshBackend: failingFirst(2)},

	// Strict-Transport-Security.
	{mwType: "headers", key: "sts_seconds", base: map[string]string{"force_sts_header": "true"},
		a: "60", b: "120", probe: get("/"), header: "Strict-Transport-Security"},
	{mwType: "headers", key: "force_sts_header", base: map[string]string{"sts_seconds": "60"},
		a: "false", b: "true", probe: get("/"), header: "Strict-Transport-Security"},
	{mwType: "headers", key: "sts_include_subdomains", base: map[string]string{"sts_seconds": "60", "force_sts_header": "true"},
		a: "false", b: "true", probe: get("/"), header: "Strict-Transport-Security"},
	{mwType: "headers", key: "sts_preload", base: map[string]string{"sts_seconds": "60", "force_sts_header": "true"},
		a: "false", b: "true", probe: get("/"), header: "Strict-Transport-Security"},

	// Body transforms.
	{mwType: "transform", key: "request_search", base: map[string]string{"request_replace": "B"},
		a: "zzz", b: "x", probe: postBody(3), backend: mirrorBackend},
	{mwType: "transform", key: "request_replace", base: map[string]string{"request_search": "x"},
		a: "A", b: "B", probe: postBody(3), backend: mirrorBackend},
	{mwType: "transform", key: "response_search", base: map[string]string{"response_replace": "there"},
		a: "zzz", b: "world", probe: get("/"), backend: textBackend("hello world", "text/plain")},
	{mwType: "transform", key: "response_replace", base: map[string]string{"response_search": "world"},
		a: "there", b: "you", probe: get("/"), backend: textBackend("hello world", "text/plain")},
	{mwType: "transform", key: "content_type", base: map[string]string{"response_search": "world", "response_replace": "you"},
		a: "text/plain", b: "application/json", probe: get("/"), backend: textBackend("hello world", "text/plain")},

	// Compression.
	{mwType: "compress", key: "algorithm", a: "gzip", b: "br",
		probe: withHeader(get("/"), "Accept-Encoding", "gzip, br"), backend: sizedBody(5000)},
	{mwType: "compress", key: "min_response_body_bytes", a: "100", b: "10000", probe: gzipGet, backend: sizedBody(5000)},
	{mwType: "compress", key: "included_content_types", a: "text/html", b: "application/json", probe: gzipGet, backend: sizedBody(5000)},
	{mwType: "compress", key: "excluded_content_types", a: "application/json", b: "text/html", probe: gzipGet, backend: sizedBody(5000)},

	// Caching: two GETs; a cached second one shows the first one's count.
	{mwType: "cache", key: "max_body_kb", base: map[string]string{"ttl_seconds": "60"},
		a: "100", b: "1", probe: get("/c"), requests: 2, freshBackend: countingBackend},

	// CORS.
	{mwType: "cors", key: "allowed_methods", base: map[string]string{"allowed_origins": "https://a.example"},
		a: "GET", b: "GET,PUT", probe: preflight("https://a.example", "PUT", ""), header: "Access-Control-Allow-Methods"},
	{mwType: "cors", key: "allowed_headers", base: map[string]string{"allowed_origins": "https://a.example"},
		a: "X-A", b: "X-B", probe: preflight("https://a.example", "GET", "x-b"), header: "Access-Control-Allow-Headers"},
	{mwType: "cors", key: "exposed_headers", base: map[string]string{"allowed_origins": "https://a.example"},
		a: "X-A", b: "X-B", probe: fromOrigin("https://a.example"), header: "Access-Control-Expose-Headers"},
	{mwType: "cors", key: "max_age", base: map[string]string{"allowed_origins": "https://a.example"},
		a: "60", b: "120", probe: preflight("https://a.example", "GET", ""), header: "Access-Control-Max-Age"},
	{mwType: "cors", key: "allow_credentials", base: map[string]string{"allowed_origins": "https://a.example"},
		a: "false", b: "true", probe: fromOrigin("https://a.example"), header: "Access-Control-Allow-Credentials"},
	{mwType: "grpcweb", key: "allow_credentials", base: map[string]string{"allowed_origins": "https://a.example"},
		a: "false", b: "true", probe: preflight("https://a.example", "POST", "content-type"), header: "Access-Control-Allow-Credentials"},
	{mwType: "grpcweb", key: "max_age", base: map[string]string{"allowed_origins": "https://a.example"},
		a: "60", b: "120", probe: preflight("https://a.example", "POST", "content-type"), header: "Access-Control-Max-Age"},

	// HMAC request signing.
	{mwType: "hmac", key: "secret", a: "s1", b: "s2", probe: signedPost("s1", "X-Signature-256", "sha256=", "hi")},
	{mwType: "hmac", key: "header", base: map[string]string{"secret": "s1"},
		a: "X-Signature-256", b: "X-Sig", probe: signedPost("s1", "X-Signature-256", "sha256=", "hi")},
	{mwType: "hmac", key: "prefix", base: map[string]string{"secret": "s1"},
		a: "sha256=", b: "v1=", probe: signedPost("s1", "X-Signature-256", "sha256=", "hi")},
	{mwType: "hmac", key: "methods", base: map[string]string{"secret": "s1"},
		a: "POST", b: "PUT", probe: postBody(3)},
	{mwType: "hmac", key: "body_limit", base: map[string]string{"secret": "s1"},
		a: "1048576", b: "1", probe: signedPost("s1", "X-Signature-256", "sha256=", "hi")},

	// Client certificate forwarding.
	{mwType: "xfcc", key: "forward_dns", a: "false", b: "true", probe: withClientCert},
	{mwType: "xfcc", key: "forward_hash", a: "false", b: "true", probe: withClientCert},
}

// htmlPage is a page the deception middleware may splice traps into.
var htmlPage = textBackend("<html><body>hi</body></html>", "text/html")

// basicGet is a GET carrying HTTP basic credentials.
func basicGet(user, pass string) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		r := get("/")(t)
		r.SetBasicAuth(user, pass)
		return r
	}
}

const jwtSecret = "0123456789abcdef0123456789abcdef"

// bearer is a GET carrying an HS256 token over claims, signed with jwtSecret.
func signedBearer(claims jwt.MapClaims) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		t.Helper()
		if _, ok := claims["exp"]; !ok {
			claims["exp"] = time.Now().Add(time.Hour).Unix()
		}
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
		if err != nil {
			t.Fatal(err)
		}
		r := get("/")(t)
		r.Header.Set("Authorization", "Bearer "+tok)
		return r
	}
}

var jwtBase = map[string]string{"type": "jwt", "secret": jwtSecret, "allow_any_audience": "true"}

func with(base map[string]string, kv ...string) map[string]string {
	out := maps.Clone(base)
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

var authKeyEffects = []keyEffect{
	// WAF switches with a rule of their own to show.
	{mwType: "waf", key: "malware_detection", a: "false", b: "true", probe: originGet("/c99.php")},
	{mwType: "waf", key: "ransomware_detection", a: "false", b: "true", probe: get("/decrypt_files.txt")},
	{mwType: "waf", key: "wordpress", a: "false", b: "true", probe: originGet("/wp-content/plugins/x.php")},
	{mwType: "waf", key: "request_body_limit", a: "1048576", b: "16", probe: postBody(4096)},
	{mwType: "waf", key: "dlp", a: "false", b: "true", probe: get("/"),
		backend: textBackend("card 4111 1111 1111 1111", "text/plain")},
	{mwType: "waf", key: "ssrf_protection", base: map[string]string{"origins": "app.example"},
		a: "false", b: "true", probe: get("/?url=http%3A%2F%2Fevil.example%2Fx")},

	// Deception.
	{mwType: "deception", key: "canary_header", base: map[string]string{"canary_token": "tok"},
		a: "X-A", b: "X-B", probe: get("/"), header: "X-B"},
	{mwType: "deception", key: "canary_token", base: map[string]string{"canary_header": "X-Canary"},
		a: "t1", b: "t2", probe: get("/"), header: "X-Canary"},
	{mwType: "deception", key: "honey_forms", a: "/f1", b: "/f2", probe: get("/"), backend: htmlPage},
	{mwType: "deception", key: "invisible_link_paths", a: "/l1", b: "/l2", probe: get("/"), backend: htmlPage},
	{mwType: "deception", key: "inject_invisible_links", base: map[string]string{"invisible_link_paths": "/l1"},
		a: "true", b: "false", probe: get("/"), backend: htmlPage},
	// With a honey form configured the page is rewritten either way; the
	// switch still decides whether the links go in.
	{mwType: "deception", key: "inject_invisible_links", base: map[string]string{"invisible_link_paths": "/l1", "honey_forms": "/f1"},
		a: "true", b: "false", probe: get("/"), backend: htmlPage},

	// Turnstile: which methods must carry a token.
	{mwType: "turnstile", key: "methods", base: map[string]string{"secret": "s"}, a: "POST", b: "GET", probe: get("/")},

	// Basic and API-key authentication.
	{mwType: "auth", key: "type", base: map[string]string{"username": "u", "password": "p", "key_x": "k"},
		a: "basic", b: "apikey", probe: basicGet("u", "p")},
	{mwType: "auth", key: "username", base: map[string]string{"type": "basic", "password": "p"},
		a: "u", b: "v", probe: basicGet("u", "p")},
	{mwType: "auth", key: "password", base: map[string]string{"type": "basic", "username": "u"},
		a: "p", b: "q", probe: basicGet("u", "p")},
	{mwType: "auth", key: "users", base: map[string]string{"type": "basic"}, a: "u:p", b: "v:q", probe: basicGet("u", "p")},
	{mwType: "auth", key: "realm", base: map[string]string{"type": "basic", "users": "u:p"},
		a: "A", b: "B", probe: get("/"), header: "WWW-Authenticate"},
	{mwType: "auth", key: "dry_run", base: map[string]string{"type": "basic", "users": "u:p"}, a: "false", b: "true", probe: get("/")},
	{mwType: "auth", key: "error_template", base: map[string]string{"type": "basic", "users": "u:p"},
		a: "", b: "nope-page", probe: get("/")},
	{mwType: "auth", key: "header", base: map[string]string{"type": "apikey", "key_k": "tenant"},
		a: "X-API-Key", b: "X-Other", probe: withHeader(get("/"), "X-API-Key", "k")},
	{mwType: "auth", key: "hashed", base: map[string]string{"type": "apikey", "key_k": "tenant"},
		a: "false", b: "true", probe: withHeader(get("/"), "X-API-Key", "k")},

	// JWT.
	{mwType: "auth", key: "secret", base: map[string]string{"type": "jwt", "allow_any_audience": "true"},
		a: jwtSecret, b: "fedcba9876543210fedcba9876543210", probe: signedBearer(jwt.MapClaims{"sub": "u"})},
	{mwType: "auth", key: "issuer", base: jwtBase, a: "https://a.example", b: "https://b.example",
		probe: signedBearer(jwt.MapClaims{"sub": "u", "iss": "https://a.example"})},
	{mwType: "auth", key: "audience", base: with(jwtBase, "allow_any_audience", "false"), a: "api-a", b: "api-b",
		probe: signedBearer(jwt.MapClaims{"sub": "u", "aud": "api-a"})},
	{mwType: "auth", key: "required_scopes", base: jwtBase, a: "read", b: "write",
		probe: signedBearer(jwt.MapClaims{"sub": "u", "scope": "read"})},
	{mwType: "auth", key: "required_roles", base: jwtBase, a: "admin", b: "ops",
		probe: signedBearer(jwt.MapClaims{"sub": "u", "roles": []string{"admin"}})},
}

func init() {
	dashboardKeyEffects = append(dashboardKeyEffects, moreKeyEffects...)
	dashboardKeyEffects = append(dashboardKeyEffects, authKeyEffects...)
}

// An auth service for the forwardauth rows. It allows a request on a rule
// named by the path it is reached at, so one server answers every row.
var forwardAuthService = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	allow := false
	switch r.URL.Path {
	case "/allow":
		allow = true
	case "/token":
		allow = r.Header.Get("X-Token") != ""
	case "/body":
		allow = len(body) > 0
	case "/body10":
		allow = len(body) == 10
	case "/method":
		allow = r.Method == http.MethodPost
	case "/xff":
		allow = r.Header.Get("X-Forwarded-For") == "203.0.113.77"
	case "/user":
		allow = true
		w.Header().Set("X-User", "alice")
	}
	if !allow {
		w.WriteHeader(http.StatusUnauthorized)
	}
}))

// forwardAuthTLS presents a certificate no client trusts.
var forwardAuthTLS = httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

func fa(path string, kv ...string) map[string]string {
	return with(map[string]string{"address": forwardAuthService.URL + path}, kv...)
}

// userBackend answers with the X-User header the gateway forwarded.
func userBackend(w http.ResponseWriter, r *http.Request) {
	_, _ = io.WriteString(w, "user="+r.Header.Get("X-User"))
}

// asTenant is a request an earlier auth middleware attributed to tenant t1.
func asTenant(base func(*testing.T) *http.Request) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		r := base(t)
		return r.WithContext(context.WithValue(r.Context(), auth.TenantIDContextKey, "t1"))
	}
}

// cycle answers with each probe in turn, so one row can send a sequence.
func cycle(probes ...func(*testing.T) *http.Request) func(*testing.T) *http.Request {
	var n atomic.Int64
	return func(t *testing.T) *http.Request {
		return probes[int(n.Add(1)-1)%len(probes)](t)
	}
}

// upload is a multipart POST of one file.
func upload(name, contentType, content string) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="file"; filename="`+name+`"`)
		h.Set("Content-Type", contentType)
		part, err := mw.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(part, content)
		_ = mw.Close()
		r := newProbe(http.MethodPost, "/upload", buf.String())
		r.Header.Set("Content-Type", mw.FormDataContentType())
		return r
	}
}

// cleanClamd is a clamd that reports every stream clean.
var cleanClamd = func() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64*1024)
				var seen []byte
				for {
					n, err := c.Read(buf)
					seen = append(seen, buf[:n]...)
					if bytes.HasSuffix(seen, []byte{0, 0, 0, 0}) || err != nil {
						break
					}
				}
				_, _ = io.WriteString(c, "stream: OK\n")
			}(c)
		}
	}()
	return "tcp://" + ln.Addr().String()
}()

// deadClamd is an address nothing listens on.
const deadClamd = "tcp://127.0.0.1:1"

var integrationKeyEffects = []keyEffect{
	// Forward auth.
	{mwType: "forwardauth", key: "address", a: forwardAuthService.URL + "/allow", b: forwardAuthService.URL + "/deny", probe: get("/")},
	{mwType: "forwardauth", key: "auth_request_headers", base: fa("/token"), a: "Authorization", b: "X-Token",
		probe: withHeader(get("/"), "X-Token", "t")},
	{mwType: "forwardauth", key: "forward_body", base: fa("/body"), a: "false", b: "true", probe: postBody(10)},
	{mwType: "forwardauth", key: "preserve_request_method", base: fa("/method"), a: "false", b: "true", probe: postBody(10)},
	{mwType: "forwardauth", key: "max_body_size", base: fa("/body10", "forward_body", "true"), a: "1048576", b: "2", probe: postBody(10)},
	{mwType: "forwardauth", key: "trust_forward_header", base: fa("/xff"), a: "false", b: "true",
		probe: withHeader(get("/"), "X-Forwarded-For", "203.0.113.77")},
	{mwType: "forwardauth", key: "auth_response_headers", base: fa("/user"), a: "X-Other", b: "X-User",
		probe: get("/"), backend: userBackend},
	{mwType: "forwardauth", key: "tls_insecure_skip_verify", base: map[string]string{"address": forwardAuthTLS.URL},
		a: "false", b: "true", probe: get("/")},

	// Upload scanning.
	{mwType: "file_security", key: "blocked_mime_types", a: "image/png", b: "text/plain", probe: upload("a.txt", "text/plain", "hello")},
	// Text types are detected with a charset; a list names the bare type.
	{mwType: "file_security", key: "blocked_mime_types", a: "", b: "text/html",
		probe: upload("a.html", "text/html", "<html><body>x</body></html>")},
	{mwType: "file_security", key: "allowed_mime_types", a: "text/plain", b: "image/png", probe: upload("a.txt", "text/plain", "hello")},
	{mwType: "file_security", key: "max_file_size", a: "1048576", b: "2", probe: upload("a.txt", "text/plain", "hello")},
	{mwType: "file_security", key: "enable_clamav", base: map[string]string{"clamav_addr": deadClamd},
		a: "false", b: "true", probe: upload("a.txt", "text/plain", "hello")},
	{mwType: "file_security", key: "clamav_addr", base: map[string]string{"enable_clamav": "true"},
		a: cleanClamd, b: deadClamd, probe: upload("a.txt", "text/plain", "hello")},

	// Positive security.
	{mwType: "schema_validation", key: "schema", a: `{"type":"array"}`, b: `{"type":"object"}`,
		probe: postJSON("/items", "[1,2]")},
	{mwType: "graphql_firewall", key: "max_complexity", a: "100", b: "2",
		probe: postJSON("/graphql", `{"query":"{ a b c d e }"}`)},

	// CORS presets.
	{mwType: "cors", key: "preset", a: "permissive", b: "restricted", probe: fromOrigin("https://x.example")},
	{mwType: "grpcweb", key: "preset", a: "permissive", b: "restricted", probe: grpcWebFrom("https://x.example")},

	// Caching and rate limiting over a sequence.
	{mwType: "ratelimit", key: "strategy", base: map[string]string{"burst": "1", "requests_per_minute": "1"},
		a: "", b: "tenant", probe: cycle(asTenant(getFrom("/", "198.51.100.31:4000")), asTenant(getFrom("/", "198.51.100.32:4000"))),
		requests: 2},

	// WAF tuning.
	{mwType: "waf", key: "dlp_action", base: map[string]string{"dlp": "true"}, a: "block", b: "redact", probe: get("/"),
		backend: textBackend("card 4111 1111 1111 1111", "text/plain")},
}

// noisy is a query value with close to six bits of entropy per byte, the
// shape of an encoded payload rather than of a word.
var noisy = func() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var sb strings.Builder
	x := uint32(2463534242)
	for range 512 {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		sb.WriteByte(alphabet[x%64])
	}
	return sb.String()
}()

var wafTuningEffects = []keyEffect{
	// The entropy fast path reads headers. A clean client's threshold is the
	// configured one plus half a bit, so 5.0 catches this value and 7.9 does not.
	{mwType: "waf", key: "entropy_threshold", a: "5.0", b: "7.9", probe: withHeader(get("/"), "X-Data", noisy)},
	{mwType: "waf", key: "disable_entropy", base: map[string]string{"entropy_threshold": "5.0"},
		a: "false", b: "true", probe: withHeader(get("/"), "X-Data", noisy)},
	// Past the ceiling the response streams uninspected (ADR 0062): the write
	// that crosses it is still read, the ones after it are not.
	{mwType: "waf", key: "response_body_limit", base: map[string]string{"dlp": "true"}, a: "1048576", b: "8", probe: get("/"),
		backend: chunkedBackend("hello", strings.Repeat("x", 20), " card 4111 1111 1111 1111")},
}

func init() {
	dashboardKeyEffects = append(dashboardKeyEffects, integrationKeyEffects...)
	dashboardKeyEffects = append(dashboardKeyEffects, wafTuningEffects...)
}
