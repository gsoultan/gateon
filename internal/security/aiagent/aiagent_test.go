// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package aiagent

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const gptbotUA = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot"

func TestClaimReadsTheAgentsToken(t *testing.T) {
	for ua, want := range map[string]string{
		gptbotUA: "GPTBot",
		"Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)":               "ClaudeBot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0)": "Claude-User",
		"Mozilla/5.0 (compatible; PerplexityBot/1.0)":                                     "PerplexityBot",
	} {
		got, ok := Claim(ua)
		if !ok || got.Name != want {
			t.Errorf("Claim(%q) = %q, %v; want %q", ua, got.Name, ok, want)
		}
	}
	for _, ua := range []string{"", "curl/8.5.0", "Mozilla/5.0 (X11; Linux x86_64) Chrome/141.0 Safari/537.36", "gptbot/1.0"} {
		if a, ok := Claim(ua); ok {
			t.Errorf("Claim(%q) = %q; it names no agent", ua, a.Name)
		}
	}
}

func TestParseReadsBothShapesAndLeavesOutWhatIsTooWide(t *testing.T) {
	doc := `{"creationTime":"2026-11-01","prefixes":[{"ipv4Prefix":"20.171.206.0/24"},` +
		`{"ipv6Prefix":"2a0a:1234::/48"},{"ipv4Prefix":"10.0.0.0/8"},{"ipv4Prefix":"nonsense"}]}`
	l, err := parse([]byte(doc), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.prefixes) != 2 || l.tooWide != 1 {
		t.Fatalf("got %v and %d too wide; want two prefixes and the /8 left out", l.prefixes, l.tooWide)
	}
	lines := "# a vendor's list\n192.0.2.7\n198.51.100.0/28 # office\n::ffff:203.0.113.0/120\n0.0.0.0/0\n"
	l, err = parse([]byte(lines), 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("198.51.100.0/28"),
		netip.MustParsePrefix("203.0.113.0/24")}
	if len(l.prefixes) != len(want) || l.tooWide != 1 {
		t.Fatalf("got %v and %d too wide; want %v and 0.0.0.0/0 left out", l.prefixes, l.tooWide, want)
	}
	for i := range want {
		if l.prefixes[i] != want[i] {
			t.Errorf("prefix %d is %v, want %v", i, l.prefixes[i], want[i])
		}
	}
}

func TestParseRefusesAListLargerThanItsRoom(t *testing.T) {
	if _, err := parse([]byte("192.0.2.1\n192.0.2.2\n192.0.2.3\n"), 2); err == nil {
		t.Fatal("a list of three was kept with room for two; half a fleet would read as fakes")
	}
}

// vendor serves a list, and serves an error once fail is set.
func vendor(t *testing.T, body string) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &fail
}

func TestVerifyJudgesOnlyWhatALoadedListCanJudge(t *testing.T) {
	srv, fail := vendor(t, `{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`)
	s := New(100, http.DefaultTransport)
	real, fake := netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("198.51.100.9")

	if got := s.Verify("GPTBot", real); got != Unverifiable {
		t.Fatalf("before any list loaded: %v, want Unverifiable", got)
	}
	s.Configure([]Source{{Agent: "GPTBot", URL: srv.URL}})
	s.Refresh(t.Context())
	if got := s.Verify("GPTBot", real); got != Verified {
		t.Errorf("a listed address: %v, want Verified", got)
	}
	if got := s.Verify("GPTBot", netip.MustParseAddr("::ffff:192.0.2.9")); got != Verified {
		t.Errorf("the listed address as IPv4-mapped IPv6: %v, want Verified", got)
	}
	if got := s.Verify("GPTBot", fake); got != Spoofed {
		t.Errorf("an unlisted address: %v, want Spoofed", got)
	}
	if got := s.Verify("ClaudeBot", fake); got != Unverifiable {
		t.Errorf("an agent with no list: %v, want Unverifiable", got)
	}

	// The vendor goes down: its last good list stays in force, or its real
	// crawler would read as a fake for the length of the outage.
	fail.Store(true)
	s.Refresh(t.Context())
	if got := s.Verify("GPTBot", real); got != Verified {
		t.Errorf("after a failed refresh: %v, want the last good list still Verified", got)
	}
}

func TestAnAgentWithAListThatNeverLoadedIsNotJudged(t *testing.T) {
	good, _ := vendor(t, "192.0.2.0/24\n")
	down, fail := vendor(t, "")
	fail.Store(true)
	s := New(100, http.DefaultTransport)
	s.Configure([]Source{{Agent: "GPTBot", URL: good.URL}, {Agent: "GPTBot", URL: down.URL}})
	s.Refresh(t.Context())
	if got := s.Verify("GPTBot", netip.MustParseAddr("198.51.100.9")); got != Unverifiable {
		t.Fatalf("got %v: the addresses the missing list names would read as fakes", got)
	}
}

func TestAnEmptyListIsNotTakenAsTheAnswer(t *testing.T) {
	srv, _ := vendor(t, "# nothing yet\n")
	s := New(100, http.DefaultTransport)
	s.Configure([]Source{{Agent: "GPTBot", URL: srv.URL}})
	s.Refresh(t.Context())
	if got := s.Verify("GPTBot", netip.MustParseAddr("192.0.2.9")); got != Unverifiable {
		t.Fatalf("got %v: an empty list would make every real crawler a fake", got)
	}
}

func TestTheBoundCoversEveryList(t *testing.T) {
	a, _ := vendor(t, "192.0.2.1\n192.0.2.2\n")
	b, _ := vendor(t, "198.51.100.1\n198.51.100.2\n")
	s := New(3, http.DefaultTransport)
	s.Configure([]Source{{Agent: "GPTBot", URL: a.URL}, {Agent: "ClaudeBot", URL: b.URL}})
	s.Refresh(t.Context())
	total := 0
	for _, n := range s.Loaded() {
		total += n
	}
	if total > 3 {
		t.Fatalf("%d prefixes in force with a bound of 3", total)
	}
	if got := s.Verify("ClaudeBot", netip.MustParseAddr("203.0.113.1")); got != Unverifiable {
		t.Errorf("the list past the bound: %v, want Unverifiable, not judged by half of itself", got)
	}
}

func TestValidateSources(t *testing.T) {
	src := func(agent, url string) *gateonv1.AIAgentRangeSource {
		return &gateonv1.AIAgentRangeSource{Agent: agent, Url: url}
	}
	if err := ValidateSources(nil, []*gateonv1.AIAgentRangeSource{
		src("GPTBot", "https://openai.com/gptbot.json"), src("ClaudeBot", "http://127.0.0.1:9000/claude.txt"),
	}); err != nil {
		t.Errorf("valid lists refused: %v", err)
	}
	for name, p := range map[string]*gateonv1.AIAgentRangeSource{
		"an unknown agent": src("NotABot", "https://example.com/x.json"),
		"plain http":       src("GPTBot", "http://example.com/gptbot.json"),
		"not a URL":        src("GPTBot", "gptbot.json"),
	} {
		if err := ValidateSources(nil, []*gateonv1.AIAgentRangeSource{p}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	stored := []*gateonv1.AIAgentRangeSource{src("GPTBot", "http://example.com/old.json")}
	if err := ValidateSources(stored, stored); err != nil {
		t.Errorf("a stored list was judged again: %v", err)
	}
	many := make([]*gateonv1.AIAgentRangeSource, maxSources+1)
	for i := range many {
		many[i] = src("GPTBot", "https://example.com/"+strings.Repeat("a", i+1))
	}
	if err := ValidateSources(nil, many); err == nil {
		t.Errorf("%d lists were accepted", len(many))
	}
}

func BenchmarkClaimOfABrowser(b *testing.B) {
	const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	b.ReportAllocs()
	for b.Loop() {
		_, _ = Claim(ua)
	}
}
