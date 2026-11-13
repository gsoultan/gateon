// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package upgrade

import (
	"errors"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/selfupdate"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func ver(t *testing.T, s string) selfupdate.Version {
	t.Helper()
	v, ok := selfupdate.ParseVersion(s)
	if !ok {
		t.Fatalf("%q is not a version", s)
	}
	return v
}

func TestScopeBoundsHowFarAnAutomaticInstallGoes(t *testing.T) {
	cases := []struct {
		scope    Scope
		from, to string
		want     bool
	}{
		{ScopePatch, "1.8.2", "1.8.3", true},
		{ScopePatch, "1.8.2", "1.9.0", false},
		{ScopePatch, "1.8.2", "2.0.0", false},
		{ScopePatch, "1.8.2", "1.8.2", false},
		{ScopePatch, "1.8.2", "1.8.1", false},
		{ScopeMinor, "1.8.2", "1.9.0", true},
		{ScopeMinor, "1.8.2", "2.0.0", false},
		{ScopeMajor, "1.8.2", "2.0.0", true},
		{ScopeMajor, "1.8.2", "1.8.1", false},
	}
	for _, c := range cases {
		if got := c.scope.Allows(ver(t, c.from), ver(t, c.to)); got != c.want {
			t.Errorf("scope %d from %s to %s: got %v, want %v", c.scope, c.from, c.to, got, c.want)
		}
	}
}

func at(hour, minute int) time.Time {
	return time.Date(2026, 11, 13, hour, minute, 0, 0, time.UTC)
}

func TestWindowContains(t *testing.T) {
	night := Window{Start: 2 * 60, End: 4 * 60}
	overMidnight := Window{Start: 23 * 60, End: 60}
	cases := []struct {
		w    Window
		t    time.Time
		want bool
	}{
		{night, at(2, 0), true},
		{night, at(3, 59), true},
		{night, at(4, 0), false},
		{night, at(1, 59), false},
		{night, at(14, 0), false},
		{overMidnight, at(23, 30), true},
		{overMidnight, at(0, 30), true},
		{overMidnight, at(1, 0), false},
		{overMidnight, at(12, 0), false},
		{Window{Start: 300, End: 300}, at(12, 0), true},
	}
	for _, c := range cases {
		if got := c.w.Contains(c.t); got != c.want {
			t.Errorf("%s contains %s: got %v, want %v", c.w, c.t.Format("15:04"), got, c.want)
		}
	}
}

func TestParseWindowRefusesWhatIsNotTwoTimesOfDay(t *testing.T) {
	if w, err := ParseWindow(" 02:00-04:30 "); err != nil || w != (Window{Start: 120, End: 270}) {
		t.Fatalf("got %+v, %v", w, err)
	}
	for _, bad := range []string{"", "02:00", "2:00-4:00", "24:00-04:00", "02:60-04:00", "02:00-04:00-06:00", "aa:bb-cc:dd", "-1:00-04:00"} {
		if _, err := ParseWindow(bad); !errors.Is(err, ErrWindow) {
			t.Errorf("%q was accepted (%v)", bad, err)
		}
	}
}

func TestValidateConfigWantsBothEndsOfAWindowOrNeither(t *testing.T) {
	ok := []*gateonv1.UpdateConfig{
		nil, {}, {AutoInstallWindowStart: "22:00", AutoInstallWindowEnd: "02:00"},
	}
	for _, c := range ok {
		if err := ValidateConfig(c); err != nil {
			t.Errorf("%v was refused: %v", c, err)
		}
	}
	bad := []*gateonv1.UpdateConfig{
		{AutoInstallWindowStart: "22:00"}, {AutoInstallWindowEnd: "02:00"},
		{AutoInstallWindowStart: "ten", AutoInstallWindowEnd: "02:00"},
	}
	for _, c := range bad {
		if err := ValidateConfig(c); !errors.Is(err, ErrWindow) {
			t.Errorf("%v was accepted (%v)", c, err)
		}
	}
}

func TestAutomaticInstallIsOffUnlessAsked(t *testing.T) {
	a := AutoSettings(nil)
	if a.Enabled || a.ByEnv || a.Scope != ScopePatch || a.Window != (Window{Start: 120, End: 240}) {
		t.Fatalf("the defaults are %+v, want off, patch releases, 02:00-04:00", a)
	}
}

func TestTheEnvironmentOverridesTheSettingEitherWay(t *testing.T) {
	t.Setenv(EnvAutoInstall, "0")
	if a := AutoSettings(&gateonv1.UpdateConfig{AutoInstall: true}); a.Enabled || !a.ByEnv {
		t.Fatalf("got %+v: the environment said off", a)
	}
	t.Setenv(EnvAutoInstall, "1")
	if a := AutoSettings(&gateonv1.UpdateConfig{}); !a.Enabled || !a.ByEnv {
		t.Fatalf("got %+v: the environment said on", a)
	}
	t.Setenv(EnvAutoInstall, "perhaps")
	if a := AutoSettings(&gateonv1.UpdateConfig{AutoInstall: true}); !a.Enabled || a.ByEnv {
		t.Fatalf("got %+v: an unreadable value must leave the setting alone", a)
	}
}

func TestTheSettingsScopeAndWindowWinOverTheEnvironments(t *testing.T) {
	t.Setenv(EnvAutoScope, "major")
	t.Setenv(EnvWindow, "10:00-11:00")
	if a := AutoSettings(&gateonv1.UpdateConfig{}); a.Scope != ScopeMajor || a.Window != (Window{Start: 600, End: 660}) {
		t.Fatalf("with nothing set, got %+v, want the environment's", a)
	}
	c := &gateonv1.UpdateConfig{
		AutoInstallScope:       gateonv1.UpdateScope_UPDATE_SCOPE_MINOR,
		AutoInstallWindowStart: "22:00", AutoInstallWindowEnd: "23:00",
	}
	if a := AutoSettings(c); a.Scope != ScopeMinor || a.Window != (Window{Start: 22 * 60, End: 23 * 60}) {
		t.Fatalf("got %+v, want the setting's", a)
	}
}

func TestAnUnreadableWindowInTheEnvironmentFallsBackToTheDefault(t *testing.T) {
	t.Setenv(EnvWindow, "whenever")
	if a := AutoSettings(nil); a.Window != (Window{Start: 120, End: 240}) {
		t.Fatalf("got %s, want the default window rather than every hour of the day", a.Window)
	}
}
