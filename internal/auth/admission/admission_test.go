// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package admission

import (
	"net/netip"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestSources(perMinute int) (*Sources, *clock) {
	c := &clock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	s := NewSources(perMinute)
	s.SetClock(c.now)
	return s, c
}

// TestSourcesRefusePastTheBurstAndEarnItBack: a client gets its burst at
// once, the next is refused with how long to wait, and the allowance comes
// back at the per-minute rate -- not all at once.
func TestSourcesRefusePastTheBurstAndEarnItBack(t *testing.T) {
	s, c := newTestSources(10)
	for i := range 10 {
		if ok, _ := s.Take("203.0.113.9:4000"); !ok {
			t.Fatalf("request %d of a burst of 10 was refused", i+1)
		}
	}
	ok, wait := s.Take("203.0.113.9:4001")
	if ok {
		t.Fatal("the 11th request in the same instant was admitted")
	}
	if wait != 6*time.Second {
		t.Errorf("retry after %v, want 6s (one request per six seconds)", wait)
	}
	c.advance(6 * time.Second)
	if ok, _ := s.Take("203.0.113.9"); !ok {
		t.Error("refused after waiting the time it was told to")
	}
	if ok, _ := s.Take("203.0.113.9"); ok {
		t.Error("six seconds earned two requests")
	}
}

// TestSourcesCountAnIPv6ClientByIts64: every address in one /64 is one
// client, and the next /64 is another; an IPv4 address is a client on its own.
func TestSourcesCountAnIPv6ClientByIts64(t *testing.T) {
	s, _ := newTestSources(2)
	for i := range 2 {
		if ok, _ := s.Take("[2001:db8:1:2::" + strconv.Itoa(i+1) + "]:443"); !ok {
			t.Fatalf("request %d from the /64 refused", i+1)
		}
	}
	if ok, _ := s.Take("2001:db8:1:2:ffff:ffff:ffff:ffff"); ok {
		t.Error("another address in the same /64 got a fresh allowance")
	}
	if ok, _ := s.Take("2001:db8:1:3::1"); !ok {
		t.Error("the next /64 shares the first one's allowance")
	}
	s.Take("198.51.100.7")
	s.Take("198.51.100.7")
	if ok, _ := s.Take("198.51.100.8"); !ok {
		t.Error("the next IPv4 address shares its neighbour's allowance")
	}
	if ok, _ := s.Take("::ffff:198.51.100.7"); ok {
		t.Error("an IPv4-mapped address is a different client from the IPv4 one")
	}
}

func TestSourceOf(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9":          "203.0.113.9/32",
		"203.0.113.9:8080":     "203.0.113.9/32",
		"[2001:db8::7]:443":    "2001:db8::/64",
		"fe80::1%en0":          "fe80::/64",
		"::ffff:192.0.2.1":     "192.0.2.1/32",
		"not an address":       "invalid Prefix",
		"":                     "invalid Prefix",
		"2001:db8:a:b:c:d:e:f": "2001:db8:a:b::/64",
		"[2001:db8:a:b::1]:0":  "2001:db8:a:b::/64",
		"127.0.0.1":            "127.0.0.1/32",
		"0000:0000::0000:0001": "::/64",
		"[::1]":                "invalid Prefix",
		"2001:db8::1/64":       "invalid Prefix",
	}
	for in, want := range cases {
		if got := SourceOf(in).String(); got != want {
			t.Errorf("SourceOf(%q) = %s, want %s", in, got, want)
		}
	}
}

// sourcesByteBound is what a full Sources may hold (ADR 0053). Measured at
// about 3 MiB; every key is a netip.Prefix, whatever the client sent.
const sourcesByteBound = 4 << 20

func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// TestSourcesAreBoundedInEntriesAndBytes: a client with a /48 has 65,536
// /64s. Stepping through them fills the table, and the table stays at
// MaxSources entries and under its byte bound, evicting the oldest.
func TestSourcesAreBoundedInEntriesAndBytes(t *testing.T) {
	s, _ := newTestSources(10)
	before := heapInUse()
	for i := range 2 * MaxSources {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, byte(i >> 8), byte(i), 15: 1})
		s.Take(a.String())
	}
	held := int64(heapInUse()) - int64(before)
	runtime.KeepAlive(s)
	t.Logf("%d clients held in %d KiB", s.Len(), held>>10)
	if s.Len() > MaxSources {
		t.Errorf("%d clients held, over MaxSources %d", s.Len(), MaxSources)
	}
	if held > sourcesByteBound {
		t.Errorf("a full table holds %d KiB, over its %d KiB bound", held>>10, sourcesByteBound>>10)
	}
	// The oldest was evicted; the newest is still counted.
	n := 2*MaxSources - 1
	last := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, byte(n >> 8), byte(n), 15: 1})
	for range 9 {
		s.Take(last.String())
	}
	if ok, _ := s.Take(last.String()); ok {
		t.Error("the most recent client's count was evicted")
	}
}

// TestGateRefusesPastItsSlotsAndKeepsTheReserveApart: the general slots are
// all anyone gets; the reserve is a separate place, and a released slot is
// free again.
func TestGateRefusesPastItsSlotsAndKeepsTheReserveApart(t *testing.T) {
	g := NewGate(2)
	if g.Size() != 3 {
		t.Fatalf("Size() = %d, want 2 general + 1 reserve", g.Size())
	}
	a, okA := g.TryEnter()
	_, okB := g.TryEnter()
	if !okA || !okB {
		t.Fatal("an empty gate of 2 refused one of two")
	}
	if _, ok := g.TryEnter(); ok {
		t.Fatal("a third general slot in a gate of 2")
	}
	r, ok := g.TryEnterReserved()
	if !ok {
		t.Fatal("the reserve was taken by the general slots")
	}
	if _, ok := g.TryEnterReserved(); ok {
		t.Fatal("two reserves")
	}
	a.Release()
	if _, ok := g.TryEnter(); !ok {
		t.Error("a released slot was not free again")
	}
	r.Release()
	if _, ok := g.TryEnterReserved(); !ok {
		t.Error("a released reserve was not free again")
	}
}

// TestGateEnterWaitsForASlotAndGivesUp: a signed-in caller's work waits for a
// slot that comes free, and is refused when none does in time.
func TestGateEnterWaitsForASlotAndGivesUp(t *testing.T) {
	g := NewGate(1)
	held, _ := g.TryEnter()
	if _, ok := g.Enter(10 * time.Millisecond); ok {
		t.Fatal("Enter got a slot from a full gate")
	}
	got := make(chan bool)
	go func() {
		s, ok := g.Enter(time.Minute)
		if ok {
			s.Release()
		}
		got <- ok
	}()
	held.Release()
	if !<-got {
		t.Error("Enter did not get the slot released while it waited")
	}
}

// TestPolicyDefaultsAndOverrides: each tier sets both bounds; the env vars
// override them; a value that is not a positive integer is ignored rather than
// switching the bound off; and the gate never takes more than half the cores.
func TestPolicyDefaultsAndOverrides(t *testing.T) {
	for _, tier := range []config.Tier{config.TierMinimal, config.TierStandard, config.TierEnterprise} {
		d := config.DefaultsFor(tier)
		if d.AuthAttemptsPerMinute < 1 || d.AuthHashConcurrency < 1 {
			t.Errorf("%s: attempts %d, hashes %d; both must be set", tier, d.AuthAttemptsPerMinute, d.AuthHashConcurrency)
		}
	}
	t.Setenv("GATEON_PROFILE", "enterprise")
	t.Setenv(AttemptsPerMinuteEnv, "")
	t.Setenv(HashConcurrencyEnv, "")
	if got := AttemptsPerMinute(); got != config.DefaultsFor(config.TierEnterprise).AuthAttemptsPerMinute {
		t.Errorf("AttemptsPerMinute() = %d, want the tier's", got)
	}
	want := min(config.DefaultsFor(config.TierEnterprise).AuthHashConcurrency, max(1, runtime.GOMAXPROCS(0)/2))
	if got := HashConcurrency(); got != want {
		t.Errorf("HashConcurrency() = %d, want %d", got, want)
	}
	prev := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(prev) })
	if got := HashConcurrency(); got != 1 {
		t.Errorf("HashConcurrency() on two cores = %d, want 1 (half of them)", got)
	}
	for _, bad := range []string{"0", "-3", "lots"} {
		t.Setenv(AttemptsPerMinuteEnv, bad)
		t.Setenv(HashConcurrencyEnv, bad)
		if AttemptsPerMinute() < 1 || HashConcurrency() < 1 {
			t.Errorf("%q switched a bound off", bad)
		}
	}
	t.Setenv(AttemptsPerMinuteEnv, "30")
	t.Setenv(HashConcurrencyEnv, "6")
	if AttemptsPerMinute() != 30 || HashConcurrency() != 6 {
		t.Errorf("overrides: attempts %d, hashes %d; want 30 and 6", AttemptsPerMinute(), HashConcurrency())
	}
}
