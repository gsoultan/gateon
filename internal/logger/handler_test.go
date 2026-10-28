// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package logger

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestHandlerWritesLevelAndTimeAsBefore: the level is now rewritten to its text
// before the JSON handler sees it, so it no longer goes through encoding/json.
// The line must not change: "level" is the level's name, at every level, and
// the time is RFC 3339 at the top of the line.
func TestHandlerWritesLevelAndTimeAsBefore(t *testing.T) {
	for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError, slog.LevelInfo + 2} {
		var buf bytes.Buffer
		slog.New(NewHandler(&buf, slog.LevelDebug, true)).Log(t.Context(), level, "m", "k", "v")
		var line map[string]any
		if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
			t.Fatalf("%v: line %q is not JSON: %v", level, buf.String(), err)
		}
		if line["level"] != level.String() {
			t.Errorf("level = %v, want %q", line["level"], level.String())
		}
		ts, _ := line["time"].(string)
		if _, err := time.Parse(time.RFC3339, ts); err != nil || strings.Contains(ts, ".") {
			t.Errorf("time = %q, want RFC 3339 without fractional seconds", ts)
		}
	}
}

// TestHandlerTakesAnAttributeNamedTime: the time rewrite read Value.Time
// without asking the kind, and Value.Time panics on any other kind, so a
// caller's own attribute named "time" -- a duration, a label -- took the
// logging goroutine down with it.
func TestHandlerTakesAnAttributeNamedTime(t *testing.T) {
	for _, useJSON := range []bool{true, false} {
		var buf bytes.Buffer
		l := slog.New(NewHandler(&buf, slog.LevelInfo, useJSON))
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("json=%v: logging an attribute named time panicked: %v", useJSON, r)
				}
			}()
			l.Info("m", "time", "12ms")
			l.WithGroup("g").Info("m", slog.Time("time", time.Time{}))
		}()
		if !strings.Contains(buf.String(), "12ms") {
			t.Errorf("json=%v: the attribute's value is missing from %q", useJSON, buf.String())
		}
	}
}
