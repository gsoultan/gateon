// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package pathbudget

import (
	"strconv"
	"testing"
)

const today = "2026-11-02"

func TestAPathOverTheHostsBudgetIsFolded(t *testing.T) {
	b := New(Limits{PathsPerHost: 3, RowsPerDay: 100})
	for i := range 3 {
		p := "/p" + strconv.Itoa(i)
		if h, got := b.Admit(today, "a.test", p); h != "a.test" || got != p {
			t.Fatalf("path %d of 3 folded into %s %s", i, h, got)
		}
	}
	if _, got := b.Admit(today, "a.test", "/scanner/1"); got != Overflow {
		t.Fatalf("the fourth path kept as %q, want %q", got, Overflow)
	}
	// An admitted path stays itself, and another host has its own budget.
	if _, got := b.Admit(today, "a.test", "/p1"); got != "/p1" {
		t.Fatalf("an admitted path came back as %q", got)
	}
	if _, got := b.Admit(today, "b.test", "/x"); got != "/x" {
		t.Fatalf("another host's first path folded into %q", got)
	}
}

func TestTheDaysBudgetBoundsEveryHost(t *testing.T) {
	b := New(Limits{PathsPerHost: 1000, RowsPerDay: 10})
	distinct := map[string]struct{}{}
	for i := range 10_000 {
		h, p := b.Admit(today, "h"+strconv.Itoa(i), "/"+strconv.Itoa(i))
		distinct[h+" "+p] = struct{}{}
	}
	// Ten admitted rows and the one row everything past them is counted in.
	if len(distinct) > 11 {
		t.Fatalf("10,000 requests made %d rows under a budget of 10", len(distinct))
	}
}

func TestANewDayStartsANewBudget(t *testing.T) {
	b := New(Limits{PathsPerHost: 1, RowsPerDay: 1})
	b.Admit(today, "a.test", "/a")
	if _, got := b.Admit("2026-11-03", "a.test", "/b"); got != "/b" {
		t.Fatalf("the next day's first path folded into %q", got)
	}
	if len(b.days) > 2 {
		t.Fatalf("the budget keeps %d days", len(b.days))
	}
}

func TestSeededRowsCountAgainstTheBudget(t *testing.T) {
	b := New(Limits{PathsPerHost: 2, RowsPerDay: 100})
	if b.Known(today) {
		t.Fatal("an empty budget knows today")
	}
	b.Seed(today, "a.test", "/a")
	b.Seed(today, "a.test", "/b")
	if !b.Known(today) {
		t.Fatal("a seeded day is not known")
	}
	if _, got := b.Admit(today, "a.test", "/c"); got != Overflow {
		t.Fatalf("a restart granted the host a second budget: /c kept as %q", got)
	}
	if _, got := b.Admit(today, "a.test", "/a"); got != "/a" {
		t.Fatalf("a stored path came back as %q", got)
	}
}

func TestEnvOverridesOnlyWhenValid(t *testing.T) {
	t.Setenv(EnvMaxPathsPerHost, "5")
	t.Setenv(EnvMaxRowsPerDay, "-1")
	got := Limits{PathsPerHost: 1, RowsPerDay: 2}.WithEnv()
	if got.PathsPerHost != 5 || got.RowsPerDay != 2 {
		t.Fatalf("WithEnv = %+v, want PathsPerHost 5 and RowsPerDay kept at 2", got)
	}
}
