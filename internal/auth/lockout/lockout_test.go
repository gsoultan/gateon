// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package lockout

import (
	"strconv"
	"testing"
	"time"
)

// clock is a settable time source.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestTracker(b Bounds) (*Tracker, *clock) {
	c := &clock{t: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	tr := New(b)
	tr.SetClock(c.now)
	return tr, c
}

// TestAPairLockDoesNotReachAnotherSource is M6's property at this level: five
// failures from one source lock that source out of that account, and leave
// another source free to try.
func TestAPairLockDoesNotReachAnotherSource(t *testing.T) {
	tr, _ := newTestTracker(DefaultBounds)
	attacker, owner := Prefix("203.0.113.9"), Prefix("198.51.100.7")
	for range PairLimit {
		if got := tr.Check("admin", attacker); got != Allow {
			t.Fatalf("attempt before the limit: %v", got)
		}
		tr.Fail("admin", attacker)
	}
	if got := tr.Check("admin", attacker); got != PairLocked {
		t.Fatalf("after %d failures the attacker's source got %v, want PairLocked", PairLimit, got)
	}
	if got := tr.Check("admin", owner); got != Allow {
		t.Fatalf("the owner's source got %v after the attacker was locked, want Allow", got)
	}
	if got := tr.Check("bob", attacker); got != Allow {
		t.Fatalf("another account from the attacker's source got %v, want Allow", got)
	}
}

// TestAPairLockLastsItsDurationThenAllowsAgain: the lock holds for PairLock
// and then the source gets a fresh allowance, so a single source is held to
// PairLimit guesses per PairLock.
func TestAPairLockLastsItsDurationThenAllowsAgain(t *testing.T) {
	tr, c := newTestTracker(DefaultBounds)
	src := Prefix("203.0.113.9")
	for range PairLimit {
		tr.Fail("admin", src)
	}
	c.advance(PairLock - time.Second)
	if got := tr.Check("admin", src); got != PairLocked {
		t.Fatalf("a second before the lock ends: %v, want PairLocked", got)
	}
	c.advance(time.Second)
	if got := tr.Check("admin", src); got != Allow {
		t.Fatalf("when the lock ends: %v, want Allow", got)
	}
	tr.Fail("admin", src)
	if got := tr.Check("admin", src); got != Allow {
		t.Fatalf("one failure into the new window: %v, want Allow", got)
	}
}

// TestSpreadGuessesPutTheAccountUnderAttack is the backstop: AccountLimit
// failures from sources that each stay under PairLimit.
func TestSpreadGuessesPutTheAccountUnderAttack(t *testing.T) {
	tr, c := newTestTracker(DefaultBounds)
	for i := range AccountLimit {
		src := Prefix("203.0." + strconv.Itoa(i) + ".1")
		if got := tr.Check("admin", src); got != Allow {
			t.Fatalf("spread attempt %d: %v, want Allow", i, got)
		}
		tr.Fail("admin", src)
	}
	fresh := Prefix("192.0.2.1")
	if got := tr.Check("admin", fresh); got != UnderAttack {
		t.Fatalf("after %d spread failures a fresh source got %v, want UnderAttack", AccountLimit, got)
	}
	// Renewed by every refusal: the attack going on keeps it in force.
	c.advance(AccountWindow - time.Minute)
	tr.Renew("admin")
	c.advance(2 * time.Minute)
	if got := tr.Check("admin", fresh); got != UnderAttack {
		t.Fatalf("after a renewal, past the first window: %v, want UnderAttack", got)
	}
	c.advance(AccountWindow)
	if got := tr.Check("admin", fresh); got != Allow {
		t.Fatalf("a window after the last renewal: %v, want Allow", got)
	}
}

// TestSuccessClearsThePairNotTheAccount: the owner signing in does not hand an
// attacker spreading guesses a fresh allowance.
func TestSuccessClearsThePairNotTheAccount(t *testing.T) {
	tr, _ := newTestTracker(DefaultBounds)
	owner := Prefix("198.51.100.7")
	for range PairLimit - 1 {
		tr.Fail("admin", owner)
	}
	tr.Succeed("admin", owner)
	tr.Fail("admin", owner)
	if got := tr.Check("admin", owner); got != Allow {
		t.Fatalf("one failure after a success: %v, want Allow (the pair count was cleared)", got)
	}
	for i := range AccountLimit - PairLimit {
		tr.Fail("admin", Prefix("203.0."+strconv.Itoa(i)+".1"))
	}
	if got := tr.Check("admin", Prefix("192.0.2.1")); got != UnderAttack {
		t.Fatalf("the owner's earlier failures stopped counting towards the account: %v", got)
	}
}

// TestTablesAreBounded: an attacker cycling sources cannot grow the tracker
// past its bounds.
func TestTablesAreBounded(t *testing.T) {
	tr, _ := newTestTracker(Bounds{Pairs: 8, Accounts: 4})
	for i := range 1000 {
		tr.Fail("user"+strconv.Itoa(i), Prefix("203.0."+strconv.Itoa(i%250)+".1"))
	}
	if n := tr.pairs.Len(); n > 8 {
		t.Errorf("pairs table holds %d entries, bound 8", n)
	}
	if n := tr.accounts.Len(); n > 4 {
		t.Errorf("accounts table holds %d entries, bound 4", n)
	}
}

func TestPrefix(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9":                "203.0.113.0/24",
		"203.0.113.200:55123":        "203.0.113.0/24",
		"[2001:db8:1:2:3:4:5:6]:443": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1":       "2001:db8:1:2::/64",
		"::ffff:198.51.100.7":        "198.51.100.0/24",
		"fe80::1%en0":                "fe80::/64",
		"":                           "",
		"not-an-address":             "",
	}
	for in, want := range cases {
		if got := Prefix(in); got != want {
			t.Errorf("Prefix(%q) = %q, want %q", in, got, want)
		}
	}
}
