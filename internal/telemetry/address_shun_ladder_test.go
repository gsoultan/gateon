// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"database/sql"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/security/mitigation"
)

// A shunned address cannot be watched while it is shunned, so a shun is not
// renewed from inside: it lapses, and an address shunned again within a day
// of its last shun lapsing is shunned for twice as long, up to a day. ADR 0031.
func TestTheShunLadder(t *testing.T) {
	now := time.Now().UTC()
	shun := func(lasted, lapsedAgo time.Duration) ipShunRow {
		end := now.Add(-lapsedAgo)
		return ipShunRow{status: statusMitigated,
			mitigatedAt: sql.NullTime{Time: end.Add(-lasted), Valid: true}, expiresAt: sql.NullTime{Time: end, Valid: true}}
	}
	for _, tc := range []struct {
		name string
		prev ipShunRow
		want time.Duration
	}{
		{"never shunned", ipShunRow{}, 15 * time.Minute},
		{"back a minute after a first shun", shun(15*time.Minute, time.Minute), 30 * time.Minute},
		{"back a minute after an 8h shun", shun(8*time.Hour, time.Minute), 16 * time.Hour},
		{"back a minute after a 16h shun: the cap", shun(16*time.Hour, time.Minute), 24 * time.Hour},
		{"back 23h after a 1h shun", shun(time.Hour, 23*time.Hour), 2 * time.Hour},
		{"back 25h after a 16h shun: a clean day starts over", shun(16*time.Hour, 25*time.Hour), 15 * time.Minute},
		{"released, then back", ipShunRow{status: statusUnmitigated,
			unmitigatedAt: sql.NullTime{Time: now.Add(-25 * time.Hour), Valid: true}}, 15 * time.Minute},
	} {
		if got := tc.prev.nextShunDuration(now); got != tc.want {
			t.Errorf("%s: shunned for %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The escalation is read from the row, so it holds across a restart and
// between the paths that shun: the second shun is twice the first.
func TestAnAddressShunnedAgainSoonAfterItLapsesIsShunnedLonger(t *testing.T) {
	onEachShunEngine(t, func(t *testing.T) {
		const ip = "198.51.100.142"
		attackFromClasses(ip, "one", ipShunMinClasses)
		if got := listedShunLength(t, ip); got != 15*time.Minute {
			t.Fatalf("the first automatic shun lasts %v, want 15m", got)
		}
		ageIPShun(t, ip, 16*time.Minute)
		attackFromClasses(ip, "two", ipShunMinClasses)
		if got := listedShunLength(t, ip); got != 30*time.Minute {
			t.Errorf("shunned again a minute after its shun lapsed, %s is shunned for %v, want 30m", ip, got)
		}
	})
}

// listedShunLength is how long ip's listed shun lasts, from the mitigation list.
func listedShunLength(t *testing.T, ip string) time.Duration {
	t.Helper()
	rows, _ := GetIPMitigations(t.Context(), 50, 0)
	for _, m := range rows {
		if m.IP == ip && m.ExpiresAt != nil {
			return m.ExpiresAt.Sub(m.MitigatedAt)
		}
	}
	t.Fatalf("%s is not listed as a lapsing shun: %+v", ip, rows)
	return 0
}

// An operator's block holds until released: an automatic shun of the same
// address changes nothing, and the list shows no end for it.
func TestAnOperatorsBlockIsNeverShortened(t *testing.T) {
	onEachShunEngine(t, func(t *testing.T) {
		const ip = "198.51.100.143"
		if err := MarkIPMitigated(ip, "Manually mitigated by administrator"); err != nil {
			t.Fatal(err)
		}
		res, err := ShunAutomatically(ip, "Anomaly detection: test")
		if err != nil || res.Outcome != ShunAlreadyInForce {
			t.Fatalf("an automatic shun of a blocked address answered %+v, %v; want already in force", res, err)
		}
		ageIPShun(t, ip, 48*time.Hour)
		if !IsIPMitigated(ip) {
			t.Error("an operator's block lapsed; it holds until released")
		}
		rows, _ := GetIPMitigations(t.Context(), 50, 0)
		if len(rows) != 1 || rows[0].ExpiresAt != nil {
			t.Errorf("the operator's block is listed as %+v, want one row with no end", rows)
		}
	})
}

// A shun in force is neither extended nor escalated by more evidence: the
// address's traffic cannot be seen while it is shunned, so a repeat is the
// threats queued before it, or another detector reading the same attack.
func TestARepeatWhileShunnedChangesNothing(t *testing.T) {
	onEachShunEngine(t, func(t *testing.T) {
		const ip = "198.51.100.144"
		first, err := ShunAutomatically(ip, "Anomaly detection: first")
		if err != nil || first.Outcome != ShunApplied {
			t.Fatalf("first shun: %+v, %v", first, err)
		}
		again, err := ShunAutomatically(ip, "Alert playbook: second")
		if err != nil || again.Outcome != ShunAlreadyInForce {
			t.Fatalf("a second shun while the first holds answered %+v, %v", again, err)
		}
		if got := listedShunLength(t, ip); got != 15*time.Minute {
			t.Errorf("a repeat while shunned left the shun at %v, want the first 15m", got)
		}
	})
}

// ShunAutomatically reads the row and then writes it, and another writer can
// land in between: the write itself refuses to shorten an operator's block or
// to override a release inside its hold.
func TestTheAutomaticWriteCannotOverwriteABlockOrARelease(t *testing.T) {
	onEachShunEngine(t, func(t *testing.T) {
		const blocked, released = "198.51.100.147", "198.51.100.148"
		if err := MarkIPMitigated(blocked, "manual"); err != nil {
			t.Fatal(err)
		}
		if _, err := ShunAutomatically(released, "first"); err != nil {
			t.Fatal(err)
		}
		if err := MarkIPUnmitigated(released); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		for _, ip := range []string{blocked, released} {
			written, err := getStore().writeAutoShun(ip, "raced", now, now.Add(autoShunBase))
			if err != nil || written {
				t.Errorf("%s: a racing automatic write went through (%v, %v)", ip, written, err)
			}
		}
		purgeShunCache()
		if !IsIPMitigated(blocked) || IsIPMitigated(released) {
			t.Errorf("after the raced writes: blocked %v (want true), released %v (want false)",
				IsIPMitigated(blocked), IsIPMitigated(released))
		}
	})
}

// Enforcement reads the end to lift a lapsed shun, and must not lift a block
// because the end is unreadable: then the status decides, as it did before
// shuns lapsed. SQLite keeps whatever text a column is given.
func TestAnUnreadableEndDoesNotTurnABlockOff(t *testing.T) {
	freshStore(t)
	const ip = "198.51.100.149"
	if _, err := ShunAutomatically(ip, "test"); err != nil {
		t.Fatal(err)
	}
	s := getStore()
	if _, err := s.db.Exec(`UPDATE ip_mitigations SET expires_at = 'not a time' WHERE ip = ?`, ip); err != nil {
		t.Fatal(err)
	}
	purgeShunCache()
	if !IsIPMitigated(ip) {
		t.Error("a shun whose end could not be read stopped being enforced")
	}
}

// Loopback and the allowlist are never shunned by an automatic path.
func TestShunAutomaticallyExemptsLoopbackAndTheAllowlist(t *testing.T) {
	freshStore(t)
	mitigation.SetAllowlist(mitigation.ParseAllowlist("203.0.113.0/24"))
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
	for _, ip := range []string{"127.0.0.1", "::1", "203.0.113.9"} {
		res, err := ShunAutomatically(ip, "test")
		if err != nil || res.Outcome != ShunExempt || IsIPMitigated(ip) {
			t.Errorf("%s: %+v, %v, shunned %v; want exempt", ip, res, err, IsIPMitigated(ip))
		}
	}
}

// leasingProvider is an eBPF provider that records how shuns reach it.
type leasingProvider struct {
	until     map[string]time.Time
	permanent map[string]bool
}

func (p *leasingProvider) GetTopIPs(int) ([]ebpf.IPStat, error)             { return nil, nil }
func (p *leasingProvider) ShunIP(ip string) error                           { p.permanent[ip] = true; return nil }
func (p *leasingProvider) UnshunIP(string) error                            { return nil }
func (p *leasingProvider) SetAdaptiveRateLimit(string, time.Duration) error { return nil }
func (p *leasingProvider) ShunIPUntil(ip string, until time.Time) error {
	p.until[ip] = until
	return nil
}

// An automatic shun reaches the kernel leased to lapse with it; an operator's
// block reaches it with no end.
func TestTheKernelShunLapsesWithTheShun(t *testing.T) {
	freshStore(t)
	p := &leasingProvider{until: map[string]time.Time{}, permanent: map[string]bool{}}
	SetEbpfManager(p)
	t.Cleanup(func() { globalEbpfManager.Store(&ebpfProviderContainer{}) })

	res, err := ShunAutomatically("198.51.100.145", "test")
	if err != nil || res.Outcome != ShunApplied {
		t.Fatalf("%+v, %v", res, err)
	}
	if got := p.until["198.51.100.145"]; !got.Equal(res.Until) || p.permanent["198.51.100.145"] {
		t.Errorf("the kernel got the automatic shun until %v (permanent: %v), want until %v",
			got, p.permanent["198.51.100.145"], res.Until)
	}
	if err := MarkIPMitigated("198.51.100.146", "manual"); err != nil {
		t.Fatal(err)
	}
	if !p.permanent["198.51.100.146"] {
		t.Error("an operator's block did not reach the kernel as one that holds until released")
	}
}

// The cache the request path reads keeps when a shun ends, and a shun past
// its end is not in force: nothing has to sweep it first.
func TestAShunPastItsEndIsNotInForce(t *testing.T) {
	past, future := shunUntil(time.Now().Add(-time.Second).UnixNano()), shunUntil(time.Now().Add(time.Minute).UnixNano())
	if past.active() || !future.active() || shunNone.active() || !shunForever.active() {
		t.Errorf("active: past %v, future %v, none %v, forever %v",
			past.active(), future.active(), shunNone.active(), shunForever.active())
	}
}
