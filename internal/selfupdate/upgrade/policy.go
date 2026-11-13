// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/selfupdate"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const (
	// EnvAutoInstall overrides the automatic-install setting, either way.
	EnvAutoInstall = "GATEON_UPDATE_AUTO_INSTALL"
	// EnvAutoScope is the scope when the setting names none: patch, minor or
	// major.
	EnvAutoScope = "GATEON_UPDATE_AUTO_SCOPE"
	// EnvWindow is the maintenance window when the setting names none:
	// "HH:MM-HH:MM", local time.
	EnvWindow = "GATEON_UPDATE_WINDOW"
)

// ErrWindow is wrapped by every refusal of a maintenance window.
var ErrWindow = errors.New("update.window")

// Scope is how far from the running release an automatic install may go.
type Scope uint8

const (
	// ScopePatch: 1.8.2 to 1.8.3, never to 1.9.0. The default: a patch
	// release is the one kind that promises to change nothing an operator
	// configured.
	ScopePatch Scope = iota
	// ScopeMinor: to any 1.x.
	ScopeMinor
	// ScopeMajor: to anything newer.
	ScopeMajor
)

// Allows reports whether an automatic install may go from cur to next.
func (s Scope) Allows(cur, next selfupdate.Version) bool {
	if !next.Newer(cur) {
		return false
	}
	switch s {
	case ScopeMajor:
		return true
	case ScopeMinor:
		return next.Major == cur.Major
	default:
		return next.Major == cur.Major && next.Minor == cur.Minor
	}
}

// Window is a daily span of local time, in minutes after midnight. Start
// equal to End is the whole day; End before Start runs through midnight.
type Window struct {
	Start, End int
}

// Contains reports whether t, in its own location, falls in the window.
func (w Window) Contains(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	switch {
	case w.Start == w.End:
		return true
	case w.Start < w.End:
		return m >= w.Start && m < w.End
	default:
		return m >= w.Start || m < w.End
	}
}

// String is the window as ParseWindow reads it.
func (w Window) String() string { return clock(w.Start) + "-" + clock(w.End) }

func clock(m int) string { return fmt.Sprintf("%02d:%02d", m/60, m%60) }

// ParseWindow reads "HH:MM-HH:MM".
func ParseWindow(s string) (Window, error) {
	from, to, ok := strings.Cut(strings.TrimSpace(s), "-")
	if !ok {
		return Window{}, fmt.Errorf("%w must be HH:MM-HH:MM, such as 02:00-04:00", ErrWindow)
	}
	start, err := ParseClock(from)
	if err != nil {
		return Window{}, err
	}
	end, err := ParseClock(to)
	if err != nil {
		return Window{}, err
	}
	return Window{Start: start, End: end}, nil
}

// ParseClock reads "HH:MM" as minutes after midnight.
func ParseClock(s string) (int, error) {
	s = strings.TrimSpace(s)
	hh, mm, ok := strings.Cut(s, ":")
	h, herr := strconv.Atoi(hh)
	m, merr := strconv.Atoi(mm)
	if !ok || len(hh) != 2 || len(mm) != 2 || herr != nil || merr != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("%w: %q is not a time of day written HH:MM", ErrWindow, s)
	}
	return h*60 + m, nil
}

// ValidateConfig refuses automatic-install settings the gateway cannot act
// on. Both ends of the window are given, or neither.
func ValidateConfig(c *gateonv1.UpdateConfig) error {
	start, end := strings.TrimSpace(c.GetAutoInstallWindowStart()), strings.TrimSpace(c.GetAutoInstallWindowEnd())
	if start == "" && end == "" {
		return nil
	}
	if start == "" || end == "" {
		return fmt.Errorf("%w needs both a start and an end, or neither", ErrWindow)
	}
	_, err := ParseWindow(start + "-" + end)
	return err
}

// Auto is the automatic-install policy in force.
type Auto struct {
	Enabled bool
	// ByEnv: EnvAutoInstall decided Enabled, so the setting cannot.
	ByEnv  bool
	Scope  Scope
	Window Window
}

// AutoSettings merges the saved settings with the environment and the
// profile's defaults.
func AutoSettings(c *gateonv1.UpdateConfig) Auto {
	a := Auto{Enabled: c.GetAutoInstall(), Scope: scopeOf(c.GetAutoInstallScope()), Window: window(c)}
	if on, set := envBool(EnvAutoInstall); set {
		a.Enabled, a.ByEnv = on, true
	} else if !a.Enabled {
		a.Enabled = config.CurrentTierDefaults().UpdateAutoInstall
	}
	return a
}

func scopeOf(s gateonv1.UpdateScope) Scope {
	switch s {
	case gateonv1.UpdateScope_UPDATE_SCOPE_PATCH:
		return ScopePatch
	case gateonv1.UpdateScope_UPDATE_SCOPE_MINOR:
		return ScopeMinor
	case gateonv1.UpdateScope_UPDATE_SCOPE_MAJOR:
		return ScopeMajor
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvAutoScope))) {
	case "minor":
		return ScopeMinor
	case "major":
		return ScopeMajor
	}
	return ScopePatch
}

// window is the setting's window, then the environment's, then the
// profile's. One that does not parse is skipped with a warning: a window is
// a restriction, and falling through to a narrower default keeps it one.
func window(c *gateonv1.UpdateConfig) Window {
	candidates := []string{os.Getenv(EnvWindow), config.CurrentTierDefaults().UpdateWindow}
	if start := strings.TrimSpace(c.GetAutoInstallWindowStart()); start != "" {
		candidates = append([]string{start + "-" + c.GetAutoInstallWindowEnd()}, candidates...)
	}
	for _, s := range candidates {
		if strings.TrimSpace(s) == "" {
			continue
		}
		w, err := ParseWindow(s)
		if err == nil {
			return w
		}
		logger.L.LogWarn("ignoring a maintenance window that cannot be read", "window", s, "error", err)
	}
	return Window{Start: 2 * 60, End: 4 * 60}
}

func envBool(name string) (on, set bool) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return false, false
	}
	on, err := strconv.ParseBool(v)
	if err != nil {
		logger.L.LogWarn("ignoring an unparseable value; automatic install stays as configured", "env", name, "value", v)
		return false, false
	}
	return on, true
}
