// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	dto "github.com/prometheus/client_model/go"
	redigo "github.com/redis/go-redis/v9"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// Fixtures for the effect rows in dashboard_key_effects_proofs_test.go: the
// services a key reaches outside the process (an identity provider, Redis,
// Cloudflare), a GeoIP database, and clients with a chosen reputation.

// ---------------------------------------------------------------- identity

// The identity provider's client, as the rows configure it.
const (
	idpClientID     = "client-1"
	idpClientSecret = "secret-1"
	idpToken        = "opaque-token-1"
)

// effectIdP is one identity provider for every auth and oidc row: OIDC
// discovery, two key sets, a token endpoint and token introspection.
var effectIdP = newEffectIdP()

type idp struct {
	srv        *httptest.Server
	key, other *rsa.PrivateKey
}

func newEffectIdP() *idp {
	p := &idp{key: mustRSAKey(), other: mustRSAKey()}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer": p.srv.URL, "jwks_uri": p.srv.URL + "/jwks",
			"authorization_endpoint": p.srv.URL + "/authorize", "token_endpoint": p.srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, jwksOf(&p.key.PublicKey)) })
	mux.HandleFunc("/jwks-other", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, jwksOf(&p.other.PublicKey)) })
	mux.HandleFunc("/token", p.token)
	// Introspection answers active only for the configured client, its
	// secret and the one token; /introspect-hinted also wants the hint.
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) { p.introspect(w, r, false) })
	mux.HandleFunc("/introspect-hinted", func(w http.ResponseWriter, r *http.Request) { p.introspect(w, r, true) })
	mux.HandleFunc("/introspect-inactive", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"active": false})
	})
	p.srv = httptest.NewServer(mux)
	return p
}

func mustRSAKey() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jwksOf(k *rsa.PublicKey) map[string]any {
	return map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "effect", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}}}
}

// signRS256 signs claims with the provider's published key.
func (p *idp) signRS256(claims jwt.MapClaims) string {
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "effect"
	s, err := tok.SignedString(p.key)
	if err != nil {
		panic(err)
	}
	return s
}

// token exchanges any code for an ID token, but only for the client that
// authenticates with idpClientSecret.
func (p *idp) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != idpClientID || secret != idpClientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]string{"error": "invalid_client"})
		return
	}
	idToken := p.signRS256(jwt.MapClaims{"iss": p.srv.URL, "aud": idpClientID, "sub": "alice", "iat": time.Now().Unix()})
	writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken})
}

func (p *idp) introspect(w http.ResponseWriter, r *http.Request, wantHint bool) {
	_ = r.ParseForm()
	f := r.PostForm
	active := f.Get("client_id") == idpClientID && f.Get("client_secret") == idpClientSecret &&
		f.Get("token") == idpToken && (!wantHint || f.Get("token_type_hint") == "access_token")
	writeJSON(w, map[string]any{"active": active, "sub": "alice"})
}

// bearerRS256 is a GET carrying a token the provider's key signed.
func bearerRS256(claims jwt.MapClaims) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		r := get("/")(t)
		r.Header.Set("Authorization", "Bearer "+effectIdP.signRS256(claims))
		return r
	}
}

// oidcLocation records an OIDC login redirect without its state, which is
// random per request: the status and where the client is sent, and with what.
func oidcLocation(rec *httptest.ResponseRecorder, _ time.Duration) string {
	loc := rec.Header().Get("Location")
	if i := strings.Index(loc, "state="); i >= 0 {
		end := strings.IndexByte(loc[i:], '&')
		if end < 0 {
			loc = loc[:i]
		} else {
			loc = loc[:i] + loc[i+end+1:]
		}
	}
	return fmt.Sprintf("%d location=%q", rec.Code, loc)
}

// oidcCallback is the browser returning from the provider: the callback with
// the state the login redirect carried, and the cookies it set.
func oidcCallback(t *testing.T, prev *httptest.ResponseRecorder) *http.Request {
	t.Helper()
	loc := prev.Header().Get("Location")
	_, query, _ := strings.Cut(loc, "?")
	state := ""
	for kv := range strings.SplitSeq(query, "&") {
		if v, ok := strings.CutPrefix(kv, "state="); ok {
			state = v
		}
	}
	if state == "" {
		t.Fatalf("the login redirect %q carries no state", loc)
	}
	r := newProbe(http.MethodGet, "/callback?code=c&state="+state, "")
	for _, c := range prev.Result().Cookies() {
		r.AddCookie(c)
	}
	return r
}

// ---------------------------------------------------------------- redis

// respRedis is a Redis server, not a client double like cache_test.go's fakeRedis: the
// rate limiter pipelines, which a double cannot answer. It speaks enough RESP for the rate limiter's sliding window and the
// response cache, and counts the commands it is sent.
type respRedis struct {
	ln       net.Listener
	mu       sync.Mutex
	strings  map[string]string
	sets     map[string]int
	commands atomic.Int64
}

// newRESPRedis starts one for the test and returns a client of it.
func newRESPRedis(t *testing.T) (*respRedis, *redigo.Client) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fr := &respRedis{ln: ln, strings: map[string]string{}, sets: map[string]int{}}
	go fr.serve()
	client := redigo.NewClient(&redigo.Options{Addr: ln.Addr().String(), Protocol: 2, DisableIdentity: true})
	t.Cleanup(func() { _ = client.Close(); _ = ln.Close() })
	return fr, client
}

func (fr *respRedis) serve() {
	for {
		c, err := fr.ln.Accept()
		if err != nil {
			return
		}
		go fr.conn(c)
	}
}

func (fr *respRedis) conn(c net.Conn) {
	defer c.Close()
	rd := bufio.NewReader(c)
	for {
		args, err := readRESP(rd)
		if err != nil {
			return
		}
		if _, err := io.WriteString(c, fr.reply(args)); err != nil {
			return
		}
	}
}

func readRESP(rd *bufio.Reader) ([]string, error) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for range n {
		if _, err := rd.ReadString('\n'); err != nil { // $len
			return nil, err
		}
		v, err := rd.ReadString('\n')
		if err != nil {
			return nil, err
		}
		args = append(args, strings.TrimSuffix(v, "\r\n"))
	}
	return args, nil
}

func (fr *respRedis) reply(args []string) string {
	if len(args) == 0 {
		return "-ERR empty\r\n"
	}
	fr.mu.Lock()
	defer fr.mu.Unlock()
	switch strings.ToUpper(args[0]) {
	case "PING":
		return "+PONG\r\n"
	case "SELECT", "CLIENT":
		return "+OK\r\n"
	}
	fr.commands.Add(1)
	switch strings.ToUpper(args[0]) {
	case "ZREMRANGEBYSCORE":
		return ":0\r\n"
	case "ZADD":
		fr.sets[args[1]]++
		return ":1\r\n"
	case "ZCARD":
		return ":" + strconv.Itoa(fr.sets[args[1]]) + "\r\n"
	case "EXPIRE":
		return ":1\r\n"
	case "GET":
		v, ok := fr.strings[args[1]]
		if !ok {
			return "$-1\r\n"
		}
		return "$" + strconv.Itoa(len(v)) + "\r\n" + v + "\r\n"
	case "SET":
		fr.strings[args[1]] = args[2]
		return "+OK\r\n"
	case "EXISTS":
		n := 0
		for _, k := range args[1:] {
			if _, ok := fr.strings[k]; ok {
				n++
			}
		}
		return ":" + strconv.Itoa(n) + "\r\n"
	}
	return "-ERR unknown command '" + args[0] + "'\r\n"
}

// withRedis gives the factory a fresh fake Redis, and the row a way to read
// how many commands it was sent.
func withRedis(seen *atomic.Pointer[respRedis]) func(*testing.T, *Factory) {
	return func(t *testing.T, f *Factory) {
		fr, client := newRESPRedis(t)
		seen.Store(fr)
		f.redisClient = client
	}
}

// withRevoked gives the factory a fresh fake Redis holding the given keys, as
// a revocation does.
func withRevoked(keys ...string) func(*testing.T, *Factory) {
	return func(t *testing.T, f *Factory) {
		fr, client := newRESPRedis(t)
		for _, k := range keys {
			fr.strings[k] = "1"
		}
		f.redisClient = client
	}
}

// redisCommands counts the commands the row's fake Redis has been sent.
func redisCommands(seen *atomic.Pointer[respRedis]) func(*testing.T) float64 {
	return func(t *testing.T) float64 {
		fr := seen.Load()
		if fr == nil {
			t.Fatal("the row has no fake Redis")
		}
		return float64(fr.commands.Load())
	}
}

// ---------------------------------------------------------------- reputation

// penalisedFrom is a GET of / from peer whose reputation stands penalty below
// perfect. Every row using it names its own /24: a score is shared by a
// network (ADR 0024), so two rows on one would score each other's clients.
func penalisedFrom(peer string, penalty float64) func(*testing.T) *http.Request {
	return penalisedGet("/", peer, penalty)
}

// penalisedGet is penalisedFrom for another path.
func penalisedGet(target, peer string, penalty float64) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		t.Helper()
		r := getFrom(target, peer+":4000")(t)
		r.Header.Set("User-Agent", "effect-registry")
		id := telemetry.GetReputationID(r)
		telemetry.ResetReputation(id)
		if penalty > 0 {
			telemetry.DecreaseReputation(id, penalty, "effect registry")
		}
		t.Cleanup(func() { telemetry.ResetReputation(id) })
		return r
	}
}

// ---------------------------------------------------------------- metrics

// routeRequests reads gateon_requests_total for a route's GETs answered 200.
func routeRequests(route string) func(*testing.T) float64 {
	return func(t *testing.T) float64 {
		var m dto.Metric
		if err := telemetry.RequestsTotal.WithLabelValues(route, "", http.MethodGet, "200").Write(&m); err != nil {
			t.Fatal(err)
		}
		return m.GetCounter().GetValue()
	}
}

// fileSize reads the size of a file under the data directory; 0 when absent.
func fileSize(rel string) func(*testing.T) float64 {
	return func(*testing.T) float64 {
		fi, err := os.Stat(filepath.Join(os.Getenv("GATEON_DATA_DIR"), rel))
		if err != nil {
			return 0
		}
		return float64(fi.Size())
	}
}

// ---------------------------------------------------------------- geoip

// geoDB writes a GeoLite2-Country database placing 198.51.100.0/24 in
// country, and nothing else anywhere, under the test's data directory. The
// format is MaxMind DB 2.0: a binary search tree over the address bits, a data
// section, and a metadata map (maxmind.github.io/MaxMind-DB).
func geoDB(country string) string {
	dir, err := os.MkdirTemp("", "gateon-geoip")
	if err != nil {
		panic(err)
	}
	path := filepath.Join(dir, country+".mmdb")
	if err := os.WriteFile(path, mmdbOf([3]byte{198, 51, 100}, country), 0o600); err != nil {
		panic(err)
	}
	geoDirs = append(geoDirs, dir)
	return path
}

// geoDirs are removed by TestMain.
var geoDirs []string

// The two databases the geoip rows switch between.
var (
	geoDE = geoDB("DE")
	geoFR = geoDB("FR")
)

func mmdbOf(prefix [3]byte, country string) []byte {
	const nodes = 24 // one per bit of the /24
	noData := uint32(nodes)
	toData := uint32(nodes) + 16 // the data section's first record, after the separator
	var tree []byte
	for i := range nodes {
		bit := prefix[i/8] >> (7 - i%8) & 1
		next := uint32(i + 1)
		if i == nodes-1 {
			next = toData
		}
		left, right := noData, noData
		if bit == 0 {
			left = next
		} else {
			right = next
		}
		tree = append(tree, byte(left>>16), byte(left>>8), byte(left), byte(right>>16), byte(right>>8), byte(right))
	}
	out := append(tree, make([]byte, 16)...)
	out = append(out, mmdbMap(1)...)
	out = append(out, mmdbString("country")...)
	out = append(out, mmdbMap(1)...)
	out = append(out, mmdbString("iso_code")...)
	out = append(out, mmdbString(country)...)
	out = append(out, "\xab\xcd\xefMaxMind.com"...)
	out = append(out, mmdbMap(9)...)
	for _, kv := range [][2][]byte{
		{mmdbString("node_count"), mmdbUint(6, nodes)},
		{mmdbString("record_size"), mmdbUint(5, 24)},
		{mmdbString("ip_version"), mmdbUint(5, 4)},
		{mmdbString("database_type"), mmdbString("GeoLite2-Country")},
		{mmdbString("languages"), {0x00, 0x04}}, // an empty array
		{mmdbString("binary_format_major_version"), mmdbUint(5, 2)},
		{mmdbString("binary_format_minor_version"), mmdbUint(5, 0)},
		{mmdbString("build_epoch"), append([]byte{0x08, 0x02}, binary.BigEndian.AppendUint64(nil, 1)...)},
		{mmdbString("description"), mmdbMap(0)},
	} {
		out = append(out, kv[0]...)
		out = append(out, kv[1]...)
	}
	return out
}

func mmdbMap(n int) []byte { return []byte{0xe0 | byte(n)} }

func mmdbString(s string) []byte { return append([]byte{0x40 | byte(len(s))}, s...) }

// mmdbUint encodes v as a one-byte uint16 (type 5) or uint32 (type 6).
func mmdbUint(typ byte, v int) []byte {
	if v == 0 {
		return []byte{typ << 5}
	}
	return []byte{typ<<5 | 1, byte(v)}
}
