// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// This is the half of the accuracy story waf_fp_corpus_test.go cannot reach.
//
// That corpus replays 405 requests against the WAF and reports a false-positive
// rate for them, and its own header says what it does not cover: the deployed
// chain refuses requests in ways that have nothing to do with request content.
// The reputation blocker, the honeypot's ban, proof-of-work and the tarpit all
// key off *client identity and history*, so a stateless replay of one request at
// a time cannot produce the state they act on and cannot measure them.
//
// That gap was not theoretical. Three separate defects were found in exactly
// this area, and every one of them was silent:
//
//   - the reputation blocker keyed on JA4+, which names a browser build rather
//     than a client, so one attacker could drive the shared score to zero and
//     403 every other user of that browser, everywhere;
//   - GATEON_MITIGATION_ALLOWLIST was honoured by one code path out of five, so
//     an allowlisted source was still refused, banned, delayed and challenged;
//   - the honeypot banned an address for 24 hours on a single trap hit, which
//     behind a shared egress takes out everyone who uses it.
//
// So this file replays *sessions*: a named client with an identity and a
// history, sending a sequence of requests, with the assertion being that a
// legitimate client is never refused because of what somebody else did.
//
// It exercises the three middlewares every route gets unconditionally
// (router.go section 3: IPMitigation, UserMitigation, ReputationBlocker). The
// opt-in ones — tarpit, proof-of-work, deception — are configuration, and a
// scenario that enabled them would measure a deployment rather than the default.

// sessionClient is one simulated client: a browser, and a place it is coming
// from.
//
// The two are separate on purpose. Sharing one and not the other is the whole
// question this file exists to ask, and every defect above came from a control
// that conflated them.
type sessionClient struct {
	name    string
	ja4Plus string
	ip      string
}

// chainStep is one request in a scenario.
type chainStep struct {
	client string
	path   string
	repeat int // 0 and 1 both mean once

	// attacker marks a step whose refusal is the control working. Its verdict is
	// not asserted — proving attacks get blocked is the attack corpus's job, and
	// asserting it here would let a scenario pass by refusing everything.
	attacker bool
}

// chainScenario is a sequence of requests from named clients, and a statement
// about what must not happen to the legitimate ones.
type chainScenario struct {
	name    string
	note    string
	clients []sessionClient
	steps   []chainStep
}

// unconditionalChain builds the enforcement every route carries.
//
// Assembled in the order router.go assembles it. A hand-made chain in a
// different order would measure something no deployment runs, which is the
// failure this project already had once when a benchmark measured its own
// harness rather than the code.
func unconditionalChain(t *testing.T, routeID string) http.Handler {
	t.Helper()
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return Chain(
		IPMitigation(),
		UserMitigation(),
		ReputationBlocker(routeID),
	)(backend)
}

// serveAs replays one request as the given client.
func serveAs(h http.Handler, c sessionClient, path string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = c.ip + ":51234"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "+
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")

	rs := &request.RequestState{JA4Plus: c.ja4Plus}
	req = req.WithContext(context.WithValue(req.Context(),
		request.RequestStateContextKey{}, rs))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// misbehave gives a client the reputation history that a burst of WAF blocks
// would have earned it, through the same function the threat pipeline uses.
//
// Driving real attacks through the chain would be a worse test, not a better
// one: it would couple this file to what the WAF happens to detect, so a rule
// change would move a number that is supposed to be about identity.
func misbehave(c sessionClient) {
	telemetry.DecreaseReputation(repid.For(c.ja4Plus, c.ip), 99,
		"chain fp harness: simulated violation history")
}

// resetChainState clears the process-wide state these middlewares act on.
//
// Reputation shards and the honeypot blocklist are package-level, so without
// this a scenario inherits whatever the previous one established and the whole
// suite measures its own execution order.
func resetChainState(t *testing.T) {
	t.Helper()
	mitigation.SetAllowlist(nil)
	blocklistMu.Lock()
	clear(honeypotBlocklist)
	clear(honeypotStrikes)
	blocklistMu.Unlock()
	t.Cleanup(func() {
		mitigation.SetAllowlist(nil)
		blocklistMu.Lock()
		clear(honeypotBlocklist)
		clear(honeypotStrikes)
		blocklistMu.Unlock()
	})
}

// chainScenarios are the shapes a real deployment produces, each one a way a
// legitimate client can end up sharing something with a bad one.
//
// Identities are made unique per scenario because reputation is process-global
// and keyed by string; two scenarios reusing a fingerprint would silently share
// a score.
func chainScenarios() []chainScenario {
	return []chainScenario{
		{
			name: "same browser, different networks",
			note: "The defect that started this. Two people running the same Chrome " +
				"build share a JA4+, which names the software and not the party. " +
				"One of them behaving badly must not refuse the other.",
			clients: []sessionClient{
				{name: "attacker", ja4Plus: "ja4-shared-browser-A", ip: "203.0.113.10"},
				{name: "bystander", ja4Plus: "ja4-shared-browser-A", ip: "198.51.100.20"},
				{name: "bystander2", ja4Plus: "ja4-shared-browser-A", ip: "192.0.2.30"},
			},
			steps: []chainStep{
				{client: "attacker", path: "/", attacker: true},
				{client: "bystander", path: "/dashboard"},
				{client: "bystander2", path: "/api/v1/orders"},
				{client: "bystander", path: "/checkout"},
			},
		},
		{
			name: "office egress, one bad laptop",
			note: "One machine behind a corporate NAT is compromised. A colleague " +
				"working from home keeps the same browser and must be unaffected. " +
				"Colleagues sharing that egress are NOT asserted here and are not " +
				"expected to survive — scoping is per network, and that limit is " +
				"pinned deliberately by TestReputationScopeSeparatesNetworksNotUsers.",
			clients: []sessionClient{
				{name: "infected", ja4Plus: "ja4-office-B", ip: "203.0.113.40"},
				{name: "home-office", ja4Plus: "ja4-office-B", ip: "198.51.100.41"},
			},
			steps: []chainStep{
				{client: "infected", path: "/", attacker: true},
				{client: "home-office", path: "/reports", repeat: 5},
			},
		},
		{
			name: "monitoring probe on a schedule",
			note: "An uptime check hits the same endpoint every few seconds from one " +
				"address forever. Volume from a single source must not by itself " +
				"become a refusal.",
			clients: []sessionClient{
				{name: "probe", ja4Plus: "ja4-probe-C", ip: "198.51.100.50"},
			},
			steps: []chainStep{{client: "probe", path: "/healthz", repeat: 200}},
		},
		{
			name: "crawler walking the site",
			note: "A search crawler fetches hundreds of distinct paths quickly from " +
				"one address. Refusing it costs the site its search ranking, which is " +
				"a business outage rather than a security event.",
			clients: []sessionClient{
				{name: "crawler", ja4Plus: "ja4-crawler-D", ip: "203.0.113.60"},
			},
			steps: []chainStep{{client: "crawler", path: "/blog/post", repeat: 150}},
		},
		{
			name: "mobile client changing address",
			note: "A phone moving between cells keeps its browser and changes its " +
				"address. Its history must not follow it in a way that refuses it at " +
				"the new one.",
			clients: []sessionClient{
				{name: "phone-cell-1", ja4Plus: "ja4-mobile-E", ip: "203.0.113.70"},
				{name: "phone-cell-2", ja4Plus: "ja4-mobile-E", ip: "198.51.100.71"},
			},
			steps: []chainStep{
				{client: "phone-cell-1", path: "/feed", repeat: 20},
				{client: "phone-cell-2", path: "/feed", repeat: 20},
			},
		},
		{
			name: "attacker rotating addresses",
			note: "The inverse case, recorded rather than asserted: scoping to a " +
				"network means a rotating attacker earns a fresh score per network. " +
				"The legitimate client sharing their browser is what is asserted.",
			clients: []sessionClient{
				{name: "rot-1", ja4Plus: "ja4-rotate-F", ip: "203.0.113.80"},
				{name: "rot-2", ja4Plus: "ja4-rotate-F", ip: "203.0.114.80"},
				{name: "rot-3", ja4Plus: "ja4-rotate-F", ip: "203.0.115.80"},
				{name: "innocent", ja4Plus: "ja4-rotate-F", ip: "198.51.100.81"},
			},
			steps: []chainStep{
				{client: "rot-1", path: "/", attacker: true},
				{client: "rot-2", path: "/", attacker: true},
				{client: "rot-3", path: "/", attacker: true},
				{client: "innocent", path: "/dashboard", repeat: 10},
			},
		},
	}
}

// runChainScenario replays one scenario and returns how many legitimate requests
// were refused.
func runChainScenario(t *testing.T, sc chainScenario) (refused, total int) {
	t.Helper()
	resetChainState(t)

	byName := make(map[string]sessionClient, len(sc.clients))
	for _, c := range sc.clients {
		byName[c.name] = c
	}
	h := unconditionalChain(t, "chain-fp-"+sc.name)

	for i, step := range sc.steps {
		c, ok := byName[step.client]
		if !ok {
			t.Fatalf("step %d names client %q, which the scenario does not define", i, step.client)
		}
		n := max(step.repeat, 1)

		if step.attacker {
			// Give the attacker the history a burst of violations would have
			// earned, then let them make their request. Their verdict is not
			// asserted; what matters is what it does to everybody else.
			misbehave(c)
			for range n {
				_ = serveAs(h, c, step.path)
			}
			continue
		}

		for range n {
			total++
			if got := serveAs(h, c, step.path); got != http.StatusOK {
				refused++
				t.Errorf("FALSE POSITIVE in %q\n"+
					"  step %d: %s (%s via %s) requested %s\n"+
					"  why legitimate: %s\n"+
					"  got %d, want 200",
					sc.name, i, c.name, c.ja4Plus, c.ip, step.path, sc.note, got)
			}
		}
	}
	return refused, total
}

// TestChainFalsePositives is the gate.
//
// A legitimate client must never be refused by the always-on chain because of
// something another client did. Unlike the WAF corpus this starts at zero
// recorded refusals rather than a ratchet, because every scenario here is one
// the composite identity and the shared allowlist were built to handle — a
// failure means one of those regressed, not that there is debt to pay down.
func TestChainFalsePositives(t *testing.T) {
	var refused, total int
	for _, sc := range chainScenarios() {
		t.Run(strings.ReplaceAll(sc.name, " ", "_"), func(t *testing.T) {
			r, n := runChainScenario(t, sc)
			refused += r
			total += n
		})
	}

	if total == 0 {
		t.Fatal("no legitimate requests were replayed; the gate would pass vacuously")
	}
	t.Logf("chain false-positive harness: %d scenarios, %d legitimate requests, "+
		"%d refused (%.2f%%)", len(chainScenarios()), total, refused,
		100*float64(refused)/float64(total))
}

// TestChainHarnessCanFail is the negative test.
//
// A harness that cannot observe a refusal reports zero forever, which is worse
// than no harness because the zero gets quoted. This drives the same chain with
// the identity the blocker actually reads and confirms it refuses — so a passing
// run above means the chain allowed the traffic, not that the harness was blind.
func TestChainHarnessCanFail(t *testing.T) {
	resetChainState(t)

	c := sessionClient{name: "doomed", ja4Plus: "ja4-negative-control", ip: "203.0.113.99"}
	h := unconditionalChain(t, "chain-fp-negative")

	if got := serveAs(h, c, "/"); got != http.StatusOK {
		t.Fatalf("a clean client got %d before any history; the harness is not "+
			"measuring what it claims", got)
	}

	misbehave(c)
	if got := serveAs(h, c, "/"); got != http.StatusForbidden {
		t.Errorf("the chain returned %d for a client with a zero reputation, want 403.\n"+
			"Every scenario in this file asserts that legitimate clients are NOT "+
			"refused, so if the chain cannot refuse anyone those assertions are "+
			"vacuous and the reported rate is meaningless.", got)
	}
}

// TestChainAllowlistCoversTheWholeChain pins the property across the trio.
//
// The allowlist reached one middleware out of five before this was found. It is
// asserted here as well as in allowlist_test.go because that file tests the
// sites individually and this one tests them assembled, which is the arrangement
// an operator actually runs.
func TestChainAllowlistCoversTheWholeChain(t *testing.T) {
	resetChainState(t)

	c := sessionClient{name: "vouched", ja4Plus: "ja4-allowlist-chain", ip: "203.0.113.120"}
	misbehave(c)

	h := unconditionalChain(t, "chain-fp-allowlist")
	if got := serveAs(h, c, "/"); got != http.StatusForbidden {
		t.Fatalf("the source was not refused without an allowlist (got %d); the rest "+
			"of this test would prove nothing", got)
	}

	mitigation.SetAllowlist(mitigation.ParseAllowlist("203.0.113.0/24"))
	if got := serveAs(h, c, "/"); got != http.StatusOK {
		t.Errorf("an allowlisted source was refused by the assembled chain (got %d). "+
			"GATEON_MITIGATION_ALLOWLIST says these sources are never mitigated.", got)
	}
}

func init() {
	// Keep the scenario names unique: two scenarios sharing one would share a
	// route label and, more importantly, read as one in the failure output.
	seen := map[string]bool{}
	for _, sc := range chainScenarios() {
		if seen[sc.name] {
			panic(fmt.Sprintf("duplicate chain scenario name %q", sc.name))
		}
		seen[sc.name] = true
	}
}
