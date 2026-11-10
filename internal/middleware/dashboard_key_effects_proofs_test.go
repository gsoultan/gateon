// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gsoultan/gateon/internal/request"
	secwaf "github.com/gsoultan/gateon/internal/security/waf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The effect rows for the keys effects-baseline.txt carried longest: those
// whose effect is outside the one response the first rows record -- at an
// identity provider, in Redis, in a log, a metric or a file, under a second
// request held in flight, or over time. Each is still a row of the same table,
// built through the same factory, and passes only when the two values answer
// differently (ADR 0048).

// introspection is a type "oauth2" auth middleware asking effectIdP.
var introspection = map[string]string{
	"type": "oauth2", "introspection_url": effectIdP.srv.URL + "/introspect",
	"client_id": idpClientID, "client_secret": idpClientSecret,
}

// oidcBase is an "oidc" middleware: the login flow against effectIdP.
var oidcBase = map[string]string{
	"issuer": effectIdP.srv.URL, "client_id": idpClientID, "client_secret": idpClientSecret,
	"redirect_url": "https://app.example/callback",
}

// opaqueBearer is a GET carrying the token effectIdP introspects as active.
var opaqueBearer = withHeader(get("/"), "Authorization", "Bearer "+idpToken)

var identityKeyEffects = []keyEffect{
	// Token introspection: the endpoint asked, the client credentials it is
	// asked with, and the hint. effectIdP answers active only to all of them.
	{mwType: "auth", key: "introspection_url", base: introspection,
		a: effectIdP.srv.URL + "/introspect", b: effectIdP.srv.URL + "/introspect-inactive", probe: opaqueBearer},
	{mwType: "auth", key: "client_id", base: introspection, a: idpClientID, b: "client-2", probe: opaqueBearer},
	{mwType: "auth", key: "client_secret", base: introspection, a: idpClientSecret, b: "secret-2", probe: opaqueBearer},
	{mwType: "auth", key: "token_type_hint", base: with(introspection, "introspection_url", effectIdP.srv.URL+"/introspect-hinted"),
		a: "", b: "access_token", probe: opaqueBearer},

	// Revocation: whether a token's ID is looked up in Redis, and under what
	// prefix. Redis holds the one revoked ID, under the default prefix.
	{mwType: "auth", key: "enable_revocation", base: jwtBase, setup: withRevoked("revoked_jti:stolen"),
		a: "false", b: "true", probe: signedBearer(jwt.MapClaims{"sub": "u", "jti": "stolen"})},
	{mwType: "auth", key: "revocation_prefix", base: with(jwtBase, "enable_revocation", "true"),
		setup: withRevoked("revoked_jti:stolen"),
		a:     "revoked_jti:", b: "other:", probe: signedBearer(jwt.MapClaims{"sub": "u", "jti": "stolen"})},

	// A key set fetched from the provider: the one that signed the token, or
	// another. Without an audience a key set is refused unless the operator
	// names the opt-out, since a provider's keys sign tokens for every client.
	{mwType: "auth", key: "jwks_url", base: map[string]string{"type": "jwt", "allow_any_audience": "true"},
		a: effectIdP.srv.URL + "/jwks", b: effectIdP.srv.URL + "/jwks-other", probe: bearerRS256(jwt.MapClaims{"sub": "u"})},
	{mwType: "auth", key: "allow_any_audience", base: map[string]string{"type": "jwt", "jwks_url": effectIdP.srv.URL + "/jwks"},
		a: "false", b: "true", refusable: true, probe: bearerRS256(jwt.MapClaims{"sub": "u", "aud": "any"})},

	// The OIDC login: where the browser is sent, as whom, back to where, for
	// which scopes -- and, on the way back, the secret the code is exchanged
	// with.
	{mwType: "oidc", key: "issuer", base: oidcBase, a: effectIdP.srv.URL, b: "http://127.0.0.1:1",
		probe: get("/"), view: oidcLocation},
	{mwType: "oidc", key: "client_id", base: oidcBase, a: idpClientID, b: "client-2", probe: get("/"), view: oidcLocation},
	{mwType: "oidc", key: "redirect_url", base: oidcBase, a: "https://app.example/callback", b: "https://app.example/cb",
		probe: get("/"), view: oidcLocation},
	{mwType: "oidc", key: "scopes", base: oidcBase, a: "openid", b: "openid,email", probe: get("/"), view: oidcLocation},
	{mwType: "oidc", key: "client_secret", base: oidcBase, a: idpClientSecret, b: "secret-2",
		probe: get("/"), requests: 2, next: oidcCallback, view: oidcLocation},
}

// fakeTurnstile stands in for Cloudflare's siteverify: a token verifies only
// when the request carries the secret "ts-1".
var fakeTurnstile = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	writeJSON(w, map[string]any{"success": r.PostForm.Get("secret") == "ts-1"})
}))

func viaFakeTurnstile(_ *testing.T, f *Factory) { f.turnstileVerifyURL = fakeTurnstile.URL }

// turnstilePost is a POST carrying a Turnstile token in header.
func turnstilePost(header string) func(*testing.T) *http.Request {
	return func(*testing.T) *http.Request {
		r := newProbe(http.MethodPost, "/form", "x")
		r.Header.Set(header, "token")
		return r
	}
}

const (
	bindingSecret1 = "0123456789abcdef0123456789abcdef"
	bindingSecret2 = "fedcba9876543210fedcba9876543210"
)

var edgeKeyEffects = []keyEffect{
	// GeoIP: the database a client is looked up in, and the lists the
	// country is held to. geoDE places 198.51.100.0/24 in DE, geoFR in FR.
	{mwType: "geoip", key: "db_path", base: map[string]string{"deny_countries": "DE"}, a: geoDE, b: geoFR, probe: get("/")},
	{mwType: "geoip", key: "deny_countries", base: map[string]string{"db_path": geoDE}, a: "FR", b: "DE", probe: get("/")},
	{mwType: "geoip", key: "allow_countries", base: map[string]string{"db_path": geoDE}, a: "DE", b: "FR", probe: get("/")},

	// Turnstile: where the token is read from, and the secret it is verified
	// with (sent to the stand-in for Cloudflare).
	{mwType: "turnstile", key: "header", base: map[string]string{"secret": "ts-1"}, setup: viaFakeTurnstile,
		a: "X-A", b: "X-B", probe: turnstilePost("X-B")},
	{mwType: "turnstile", key: "secret", setup: viaFakeTurnstile, a: "ts-1", b: "ts-2",
		probe: turnstilePost("CF-Turnstile-Response")},

	// TLS session binding: which cookie is the session, and the key its
	// binding is signed with.
	{mwType: "tls_binding", key: "cookie_name", base: map[string]string{"secret": bindingSecret1},
		a: "session", b: "sid", probe: withCookie(get("/"), "sid", "s1")},
	{mwType: "tls_binding", key: "secret", a: bindingSecret1, b: bindingSecret2, probe: boundSession(bindingSecret1)},

	// Client certificate forwarding: the URI SAN.
	{mwType: "xfcc", key: "forward_uri", a: "false", b: "true", probe: withURICert("spiffe://example.org/client")},

	// In-flight limits: a request is held at the backend while the probe
	// arrives, from the same client and from another.
	{mwType: "inflightreq", key: "amount", a: "2", b: "1",
		hold: getFrom("/", "198.51.100.40:4000"), probe: getFrom("/", "198.51.100.40:4000")},
	{mwType: "inflightreq", key: "per_ip", base: map[string]string{"amount": "1"}, a: "true", b: "false",
		hold: getFrom("/", "198.51.100.41:4000"), probe: getFrom("/", "198.51.100.42:4000")},

	// A named access-log or metrics view records under its own name; unnamed
	// it passes the request through, since the route already records itself.
	{mwType: "accesslog", key: "route", a: "", b: "effect-view-log", probe: get("/"), logged: "route=effect-view-log"},
	{mwType: "metrics", key: "route", a: "", b: "effect-view-metrics", probe: get("/"),
		measure: routeRequests("effect-view-metrics")},
}

// chromeUA claims a browser that sends Sec-Fetch-* headers.
const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"

var botBase = map[string]string{"enable_js_challenge": "true", "secret_key": "bot-1"}

var challengeKeyEffects = []keyEffect{
	// Bot management: the checks it runs, the key its pass is signed with,
	// and how long a pass lasts.
	{mwType: "bot_management", key: "enable_browser_integrity", a: "false", b: "true", probe: withUA(chromeUA)},
	{mwType: "bot_management", key: "enable_js_challenge", a: "false", b: "true", probe: withUA(chromeUA), view: statusOnly},
	{mwType: "bot_management", key: "secret_key", base: botBase, a: "bot-1", b: "bot-2",
		probe: withBotPass("bot-1", 0), view: statusOnly},
	{mwType: "bot_management", key: "challenge_timeout", base: botBase, a: "3600", b: "60",
		probe: withBotPass("bot-1", 2*time.Minute), view: statusOnly},

	// Proof of work, for a client whose threat score is 50: whether it is
	// challenged, how hard the challenge is, and the key a solution from
	// another instance must have been issued under.
	{mwType: "pow", key: "threshold", base: map[string]string{"difficulty": "1", "secret": "pow-1"},
		a: "60", b: "5", probe: penalisedFrom("100.64.10.1", 50), view: statusOnly},
	{mwType: "pow", key: "difficulty", base: map[string]string{"threshold": "5", "secret": "pow-1"},
		a: "1", b: "2", probe: penalisedFrom("100.64.11.1", 50), view: headerView("X-Gateon-Pow-Difficulty")},
	{mwType: "pow", key: "secret", route: "effect-pow", base: map[string]string{"threshold": "5", "difficulty": "1"},
		a: "pow-1", b: "pow-2", probe: powSolved("pow-1", "effect-pow", "100.64.12.1"), view: statusOnly},

	// Tarpit, for a client whose threat score is 50, on a fake clock: the
	// delay is the base scaled by the score over the threshold, capped.
	{mwType: "tarpit", key: "base_delay", base: map[string]string{"max_delay": "10s", "threshold": "10"}, fakeClock: true,
		a: "100ms", b: "200ms", probe: penalisedFrom("100.64.20.1", 50), view: delayView},
	{mwType: "tarpit", key: "max_delay", base: map[string]string{"base_delay": "1s", "threshold": "10"}, fakeClock: true,
		a: "2s", b: "3s", probe: penalisedFrom("100.64.21.1", 50), view: delayView},
	{mwType: "tarpit", key: "threshold", base: map[string]string{"base_delay": "100ms", "max_delay": "10s"}, fakeClock: true,
		a: "60", b: "10", probe: penalisedFrom("100.64.22.1", 50), view: delayView},

	// Entropy: a body of close to six bits a byte is recorded as a threat
	// under a threshold of 5 and not under one of 7.9.
	{mwType: "entropy", key: "threshold", a: "7.9", b: "5.0",
		probe:  func(*testing.T) *http.Request { return newProbe(http.MethodPost, "/upload", noisy) },
		logged: "high_entropy_payload"},

	// Deception: a low-reputation client springing a trap is answered with a
	// stream that does not end, rather than 403. The writer fails after one
	// chunk, as a client that hangs up does, so the row ends.
	{mwType: "deception", key: "enable_troll_response", base: map[string]string{"honeypot_paths": "/trap"},
		a: "false", b: "true", probe: penalisedGet("/trap", "100.64.30.1", 60), writeCap: 4096, fakeClock: true,
		view: func(rec *httptest.ResponseRecorder, _ time.Duration) string {
			return fmt.Sprintf("%d type=%q bytes=%d", rec.Code, rec.Header().Get("Content-Type"), rec.Body.Len())
		}},
}

var redisRL, redisCache atomic.Pointer[respRedis]

var stateKeyEffects = []keyEffect{
	// Where the count and the cache live: this process, or Redis.
	{mwType: "ratelimit", key: "storage", base: map[string]string{"burst": "1", "requests_per_minute": "1"},
		setup: withRedis(&redisRL), measure: redisCommands(&redisRL),
		a: "local", b: "redis", probe: getFrom("/", "198.51.100.50:4000"), requests: 2},
	{mwType: "cache", key: "storage", base: map[string]string{"ttl_seconds": "60"},
		setup: withRedis(&redisCache), measure: redisCommands(&redisCache),
		a: "memory", b: "redis", probe: get("/c"), requests: 2, freshBackend: numberedBackend},

	// Over time, on a fake clock.
	{mwType: "ratelimit", key: "requests_per_minute", base: map[string]string{"burst": "1"},
		a: "1", b: "60", probe: getFrom("/", "198.51.100.51:4000"), requests: 2, pause: 1500 * time.Millisecond},
	{mwType: "cache", key: "ttl_seconds", a: "1", b: "60", probe: get("/c"), requests: 2, pause: 2 * time.Second,
		freshBackend: numberedBackend},
	{mwType: "circuit_breaker", key: "sleep_window", base: map[string]string{"min_requests": "1", "error_threshold": "0.5"},
		a: "1s", b: "1h", probe: get("/"), requests: 2, pause: 2 * time.Second, freshBackend: failingFirst(1)},
	{mwType: "circuit_breaker", key: "window_size",
		base: map[string]string{"min_requests": "2", "error_threshold": "0.5", "sleep_window": "1h"},
		a:    "1s", b: "1h", probe: get("/"), requests: 3, pause: 2 * time.Second, backend: failingBackend},

	// The memory cache bounds each of its 16 shards at max_entries/16. Of 17
	// paths two share a shard, so a bound of one an entry a shard evicts one
	// of them before the second pass asks for it again.
	{mwType: "cache", key: "max_entries", a: "1600", b: "16", probe: seventeenPaths(), requests: 34,
		freshBackend: numberedBackend},
}

func init() {
	dashboardKeyEffects = append(dashboardKeyEffects, identityKeyEffects...)
	dashboardKeyEffects = append(dashboardKeyEffects, edgeKeyEffects...)
	dashboardKeyEffects = append(dashboardKeyEffects, challengeKeyEffects...)
	dashboardKeyEffects = append(dashboardKeyEffects, stateKeyEffects...)
	dashboardKeyEffects = append(dashboardKeyEffects, wafPolicyEffects...)
}

// deepPath has more segments than the protocol rule on path depth allows.
var deepPath = strings.Repeat("/a", 20)

var scoringRule struct {
	once sync.Once
	err  error
}

// withScoringRule stores, once, an operator rule that scores a request
// carrying effect-anomaly-token instead of blocking it. The rule store is the
// process's, as on a gateway; nothing else in this package sends the token.
func withScoringRule(t *testing.T, _ *Factory) {
	t.Helper()
	scoringRule.once.Do(func() {
		if secwaf.GetStore() == nil {
			if scoringRule.err = secwaf.InitStore("sqlite::memory:"); scoringRule.err != nil {
				return
			}
		}
		scoringRule.err = secwaf.GetStore().AddRule(context.Background(), &secwaf.Rule{
			Name: "effect registry scoring rule", Format: secwaf.FormatGateon, Enabled: true, ParanoiaLevel: 1,
			Definition: `{"phase":"request_headers","targets":["args"],` +
				`"operator":{"kind":"contains","pattern":"effect-anomaly-token"},` +
				`"action":"score","severity":"critical","confidence":"high","msg":"effect registry scoring rule"}`,
		})
	})
	if scoringRule.err != nil {
		t.Fatalf("store the scoring rule: %v", scoringRule.err)
	}
}

// scoredBy is base with the reputation identity.ReputationBlocker records for
// a client in the request state.
func scoredBy(base func(*testing.T) *http.Request, reputation float64) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		r := base(t)
		return r.WithContext(request.WithState(r.Context(), &request.RequestState{Reputation: reputation}))
	}
}

// postForm is a POST of a form body.
func postForm(target, body string) func(*testing.T) *http.Request {
	return func(*testing.T) *http.Request {
		r := newProbe(http.MethodPost, target, body)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
}

var wafPolicyEffects = []keyEffect{
	{mwType: "waf", key: "protocol", a: "true", b: "false", probe: get(deepPath)},
	// Shellshock in a body is a paranoia-level-2 rule (1151009).
	{mwType: "waf", key: "paranoia_level", a: "1", b: "2", probe: postForm("/form", "x=%28%29+%7B+%3A%3B+%7D")},
	// A client gateon scores hostile is refused by the reputation rules only
	// when they are on. The route chain's reputation blocker puts the score
	// in the request state ahead of the WAF (router.go); the probe carries it
	// as that would.
	{mwType: "waf", key: "ip_reputation", a: "false", b: "true", probe: scoredBy(get("/"), 10)},
	// An issue tracker stores attack text in an issue's description.
	{mwType: "waf", key: "app_profiles", a: "", b: "issue_tracker",
		probe: postForm("/rest/api/2/issue", "description=1%27+OR+%271%27%3D%271")},
	// The threshold an operator's scoring rules accumulate to. gateon's own
	// corpus and gwaf's core only block outright, so the score that reaches a
	// threshold is from rules an operator writes with action "score" -- here
	// one critical rule, worth 5, on a token nothing else carries.
	{mwType: "waf", key: "anomaly_threshold", setup: withScoringRule, a: "5", b: "10",
		probe: get("/?q=effect-anomaly-token")},
	// The audit log a route writes, and whether it records what was allowed.
	{mwType: "waf", key: "audit_log_path", a: "effect-a.log", b: "effect-b.log",
		probe: get("/?id=1%27%20OR%20%271%27%3D%271"), measure: fileSize("audit/waf/effect-b.log")},
	{mwType: "waf", key: "audit_log_relevant_only", base: map[string]string{"audit_log_path": "effect-relevant.log"},
		a: "true", b: "false", probe: get("/benign"), measure: fileSize("audit/waf/effect-relevant.log")},
}

// statusOnly records the status: a challenge page carries a fresh challenge
// each time, so its body would differ between two identical builds.
func statusOnly(rec *httptest.ResponseRecorder, _ time.Duration) string {
	return strconv.Itoa(rec.Code)
}

// headerView records the status and one header.
func headerView(name string) func(*httptest.ResponseRecorder, time.Duration) string {
	return func(rec *httptest.ResponseRecorder, _ time.Duration) string {
		return fmt.Sprintf("%d %s=%q", rec.Code, name, rec.Header().Get(name))
	}
}

// delayView records the status and how long the response took, which on the
// bubble's clock is exactly the delay the middleware chose.
func delayView(rec *httptest.ResponseRecorder, took time.Duration) string {
	return fmt.Sprintf("%d after %v", rec.Code, took)
}

// numberedBackend answers, cacheably, with how many requests it has served.
func numberedBackend() http.HandlerFunc {
	var n atomic.Int64
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = io.WriteString(w, "served="+strconv.FormatInt(n.Add(1), 10))
	}
}

// seventeenPaths asks for /p0 to /p16, twice.
func seventeenPaths() func(*testing.T) *http.Request {
	probes := make([]func(*testing.T) *http.Request, 17)
	for i := range probes {
		probes[i] = get("/p" + strconv.Itoa(i))
	}
	return cycle(probes...)
}

// withBotPass is a browser GET carrying a bot-management pass issued age ago
// under secret, for this client.
//
// The pass is minted here rather than earned: the age is the point of one
// row, and no flow can issue a pass in the past. The format is
// challenge.passFor's -- the issue time in milliseconds and an HMAC over a
// length-prefixed context, the time, the User-Agent and the address. Should it
// change, the pass stops verifying under either value and both rows fail as
// having no effect, rather than passing.
func withBotPass(secret string, age time.Duration) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		r := withUA(chromeUA)(t)
		issued := strconv.FormatInt(time.Now().Add(-age).UnixMilli(), 10)
		mac := hmac.New(sha256.New, []byte(secret))
		for _, f := range []string{"gateon-bot-pass-v3", issued, chromeUA, "198.51.100.10"} {
			_ = binary.Write(mac, binary.BigEndian, uint64(len(f)))
			_, _ = io.WriteString(mac, f)
		}
		r.AddCookie(&http.Cookie{Name: "gateon_bot_challenge", Value: issued + "." + hex.EncodeToString(mac.Sum(nil))})
		return r
	}
}

// powSolved is a request from peer (threat score 50) answering a challenge a
// pow middleware with secret issued on route: built through the factory,
// asked, and solved here.
func powSolved(secret, route, peer string) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		t.Helper()
		cfg := map[string]string{"threshold": "5", "difficulty": "1", "secret": secret}
		issuer, err := NewFactory(nil, nil, nil, nil, t.TempDir()).Create(
			&gateonv1.Middleware{Id: "effect", Type: "pow", Config: cfg}, route)
		if err != nil {
			t.Fatal(err)
		}
		ask := penalisedFrom(peer, 50)(t)
		ask.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()
		issuer(http.HandlerFunc(echoBackend)).ServeHTTP(rec, ask)
		var ch struct {
			ID         string `json:"challenge_id"`
			Difficulty int    `json:"difficulty"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil || ch.ID == "" {
			t.Fatalf("no challenge issued (%d %q): %v", rec.Code, rec.Body.String(), err)
		}
		for n := 0; ; n++ {
			nonce := strconv.Itoa(n)
			sum := sha256.Sum256([]byte(ch.ID + nonce))
			if solution := hex.EncodeToString(sum[:]); strings.HasPrefix(solution, strings.Repeat("0", ch.Difficulty)) {
				answer := getFrom("/", peer+":4000")(t)
				answer.Header.Set("User-Agent", ask.UserAgent())
				answer.Header.Set("X-Gateon-Pow-ID", ch.ID)
				answer.Header.Set("X-Gateon-Pow-Nonce", nonce)
				answer.Header.Set("X-Gateon-Pow-Solution", solution)
				return answer
			}
		}
	}
}

func withCookie(base func(*testing.T) *http.Request, name, value string) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		r := base(t)
		r.AddCookie(&http.Cookie{Name: name, Value: value})
		return r
	}
}

// boundSession is a request over TLS with a client certificate, carrying a
// session cookie and the binding a tls_binding middleware with secret issued
// for it on that certificate.
func boundSession(secret string) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		t.Helper()
		issuer, err := NewFactory(nil, nil, nil, nil, t.TempDir()).Create(
			&gateonv1.Middleware{Id: "issuer", Type: "tls_binding", Config: map[string]string{"secret": secret}}, "issuer")
		if err != nil {
			t.Fatal(err)
		}
		login := withClientCert(t)
		rec := httptest.NewRecorder()
		issuer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "s1", Path: "/"})
		})).ServeHTTP(rec, login)
		r := get("/")(t)
		r.TLS = login.TLS
		cookies := rec.Result().Cookies()
		if len(cookies) != 2 {
			t.Fatalf("the issuing middleware set %d cookies, want the session and its binding", len(cookies))
		}
		for _, c := range cookies {
			r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
		return r
	}
}

// withURICert is a request over TLS presenting a client certificate whose
// subject alternative name is uri.
func withURICert(uri string) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "client.example"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{u},
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
}
