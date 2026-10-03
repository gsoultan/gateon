// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// challengeServer serves bot management with the JS challenge on, behind a
// mux that routes only pattern -- what the router does for a route whose rule
// is PathPrefix(pattern): a request for any other path never reaches the
// route's middleware and is answered 404.
func challengeServer(t *testing.T, pattern string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var reached atomic.Int32
	route := BotManagement(BotManagementConfig{
		Enabled: true, EnableJSChallenge: true, SecretKey: botSecret, ChallengeTimeoutSeconds: 3600,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		_, _ = io.WriteString(w, "origin")
	}))
	mux := http.NewServeMux()
	mux.Handle(pattern, route)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &reached
}

// client is a real HTTP client with a cookie jar and a fixed User-Agent.
type client struct {
	http *http.Client
	ua   string
}

func newClient(t *testing.T) *client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &client{http: &http.Client{Jar: jar}, ua: botUA}
}

// do sends one request and returns its status and body.
func (c *client) do(t *testing.T, method, target string, header map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", c.ua)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, string(body)
}

var pageChallenge = regexp.MustCompile(`var id = "([^"]+)", bits = +(\d+) *, method = "([A-Z]+)"`)

// runPage does what the page's script does, request for request: find the
// nonce, answer at the page's own URL, ask whether the pass stuck. It fails
// the test if the script would request any other path, because on a route
// with a path rule that request is not the route's.
func (c *client) runPage(t *testing.T, pageURL, page string) {
	t.Helper()
	if strings.Contains(page, "/_gateon/") {
		t.Fatalf("the challenge page's script requests a /_gateon/ path, which a route whose rule is "+
			"a path prefix never receives, so the page can never finish:\n%s", page)
	}
	m := pageChallenge.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("the challenge page carries no challenge to solve:\n%s", page)
	}
	bits, _ := strconv.Atoi(m[2])
	nonce := ""
	for n := 0; nonce == ""; n++ {
		if workDone(m[1], strconv.Itoa(n), uint(bits)) {
			nonce = strconv.Itoa(n)
		}
	}
	if code, body := c.do(t, m[3], pageURL, map[string]string{
		HeaderChallenge: challengeAnswer, HeaderChallengeID: m[1], HeaderChallengeNonce: nonce,
	}); code != http.StatusNoContent {
		t.Fatalf("the answer at %s: %d %q, want 204", pageURL, code, body)
	}
	if code, _ := c.do(t, m[3], pageURL, map[string]string{HeaderChallenge: challengeCheck}); code != http.StatusNoContent {
		t.Fatalf("the check at %s after a correct answer: %d, want 204", pageURL, code)
	}
}

// TestChallengeCanBeSolvedOnAPrefixedRoute is T9. On a route whose rule is
// PathPrefix(`/app`), the page used to fetch /_gateon/seed and post to
// /_gateon/challenge; routing runs before middleware, so both were 404 and
// every visitor was held on the challenge for ever. A client that runs the
// page must reach the origin, at whatever path it was challenged.
func TestChallengeCanBeSolvedOnAPrefixedRoute(t *testing.T) {
	srv, reached := challengeServer(t, "/app/")
	b := newClient(t)
	pageURL := srv.URL + "/app/deep/page?tab=2"

	code, page := b.do(t, http.MethodGet, pageURL, nil)
	if code != http.StatusForbidden || reached.Load() != 0 {
		t.Fatalf("first visit: %d, origin reached %d times; want the challenge and no origin", code, reached.Load())
	}
	b.runPage(t, pageURL, page)
	if reached.Load() != 0 {
		t.Fatal("the page's own requests reached the origin")
	}
	if code, body := b.do(t, http.MethodGet, pageURL, nil); code != http.StatusOK || body != "origin" {
		t.Fatalf("after running the page: %d %q, want the origin", code, body)
	}
}

// TestAClientThatDoesNotRunTheScriptDoesNotPass is the curl bypass (T23), on
// a route that matches every path, as a Host() route does: there the old
// /_gateon/ endpoints did reach the middleware. curl fetched the seed, waited
// two seconds and posted it back -- no JavaScript, no work. Now nothing a
// client can fetch is redeemable without the work.
func TestAClientThatDoesNotRunTheScriptDoesNotPass(t *testing.T) {
	srv, reached := challengeServer(t, "/")
	curl := newClient(t)
	curl.ua = "curl/8.4.0"

	if code, body := curl.do(t, http.MethodGet, srv.URL+"/_gateon/seed", nil); code == http.StatusOK {
		t.Fatalf("a client that never ran the page was handed a redeemable seed by /_gateon/seed: %q", body)
	}
	code, page := curl.do(t, http.MethodGet, srv.URL+"/page", nil)
	m := pageChallenge.FindStringSubmatch(page)
	if code != http.StatusForbidden || m == nil {
		t.Fatalf("first visit: %d, want the challenge page with a challenge:\n%s", code, page)
	}
	// Everything the page hands over, sent back without the work.
	curl.do(t, http.MethodGet, srv.URL+"/page", map[string]string{
		HeaderChallenge: challengeAnswer, HeaderChallengeID: m[1], HeaderChallengeNonce: unsolvedNonce(t, m[1]),
	})
	curl.do(t, http.MethodGet, srv.URL+"/page", map[string]string{"Cookie": ChallengeCookieName + "=" + m[1]})
	if code, _ := curl.do(t, http.MethodGet, srv.URL+"/page", nil); code == http.StatusOK || reached.Load() != 0 {
		t.Fatalf("a client that did not run the script got %d and reached the origin %d times", code, reached.Load())
	}
}

// TestChallengePageReflectsNothingFromTheRequest: the page used to carry the
// request URI into a form field; it now carries nothing the client wrote, so
// a crafted path has nowhere to land.
func TestChallengePageReflectsNothingFromTheRequest(t *testing.T) {
	h, _ := botRoute(t)
	req := botRequest(http.MethodGet, "/", botUA)
	req.URL.Path = `/"><base href="https://evil.example/"></script><script>alert(1)</script>`
	req.URL.RawQuery = url.Values{"q": {`"</script><script>alert(2)</script>`}}.Encode()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Checking your browser") {
		t.Fatalf("no challenge page served:\n%s", body)
	}
	for _, bad := range []string{"<base", "evil.example", "alert(1)", "alert(2)"} {
		if strings.Contains(body, bad) {
			t.Errorf("the request reached the challenge page as %q:\n%s", bad, body)
		}
	}
}

// TestChallengePageIsUsableWithoutSightOrScript pins what makes the page
// accessible: a language, one heading, a live status line the script writes
// progress and failures to, a <noscript> explanation, and a Try again button
// that starts hidden -- a failed check waits for the reader instead of
// reloading by itself.
func TestChallengePageIsUsableWithoutSightOrScript(t *testing.T) {
	h, _ := botRoute(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, botRequest(http.MethodGet, "/", botUA))
	body := rec.Body.String()
	for _, want := range []string{
		`<html lang="en">`,
		`<h1>Checking your browser</h1>`,
		`role="status" aria-live="polite"`,
		`<noscript>`,
		`<button id="gateon-challenge-retry" type="button" hidden>Try again</button>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the challenge page lacks %s", want)
		}
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q: a cached challenge page hands one client's challenge to another", got)
	}
}

// TestBrowserHeaderCheck pins what "Browser Integrity" checks, now that its
// label says so: a client that claims a modern browser must send the fetch
// metadata such browsers send; a client that claims nothing is not judged.
func TestBrowserHeaderCheck(t *testing.T) {
	const firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
	cases := []struct {
		name     string
		ua       string
		fetchSec bool
		pass     bool
	}{
		{"chrome without fetch metadata", botUA, false, false},
		{"chrome with fetch metadata", botUA, true, true},
		{"firefox without fetch metadata", firefox, false, false},
		{"firefox with fetch metadata", firefox, true, true},
		{"no user agent", "", false, false},
		{"curl makes no browser claim", "curl/8.4.0", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("User-Agent", tc.ua)
			if tc.fetchSec {
				req.Header.Set("Sec-Fetch-Mode", "navigate")
			}
			if got := checkBrowserIntegrity(req); got != tc.pass {
				t.Errorf("checkBrowserIntegrity = %v, want %v", got, tc.pass)
			}
		})
	}
}
