// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package logger

import (
	"bytes"
	"log/slog"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLineLimiterSkipTakesNoLock is review 3's F4. Skip runs for every refused
// request past the per-second budget -- each WAF block and each failed proxied
// request under attack -- and it took the limiter's mutex, so every core
// serialised on it exactly when the gateway was busiest; Allow took the same
// mutex on every call while anything was pending, which under attack is
// always. The mutex profile records each wait with the stack that held the
// lock, so a wait recorded in the limiter is a lock on the request path. The
// calls are made as the WAF and the proxy make them, and the report must
// still count every line under its key.
func TestLineLimiterSkipTakesNoLock(t *testing.T) {
	buf := captureL(t)
	prev := runtime.SetMutexProfileFraction(1)
	t.Cleanup(func() { runtime.SetMutexProfileFraction(prev) })

	l := NewLineLimiter(LineLimit{Level: slog.LevelInfo, Summary: "left out", PerSecond: 1, Every: time.Hour,
		Labels: [2]string{"rule", "route"}})
	routes := []string{"shop", "api", "admin"}
	const workers, perWorker = 16, 20000
	var wg sync.WaitGroup
	var written atomic.Int64
	now := time.Now()
	for w := range workers {
		wg.Go(func() {
			for i := range perWorker {
				if l.Allow(now) {
					written.Add(1)
					continue
				}
				l.Skip(now, "942100", routes[(w+i)%len(routes)])
			}
		})
	}
	wg.Wait()

	var prof bytes.Buffer
	if err := pprof.Lookup("mutex").WriteTo(&prof, 1); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(prof.String(), "(*LineLimiter)."); n > 0 {
		t.Errorf("the limiter waited on a lock %d times", n)
	}

	l.Flush()
	total := int(written.Load())
	for _, m := range regexp.MustCompile(`route=(\w+) not_written=(\d+)`).FindAllStringSubmatch(buf.String(), -1) {
		n, _ := strconv.Atoi(m[2])
		total += n
	}
	if written.Load() != 1 || total != workers*perWorker || strings.Count(buf.String(), "left out") != len(routes) {
		t.Errorf("reported %d lines in %d report lines, want %d in %d:\n%s",
			total, strings.Count(buf.String(), "left out"), workers*perWorker, len(routes), buf.String())
	}
}

// BenchmarkLineLimiterSkip is the cost of a refused request's suppressed line
// with every core refusing at once.
func BenchmarkLineLimiterSkip(b *testing.B) {
	l := NewLineLimiter(LineLimit{Level: slog.LevelInfo, Summary: "left out", PerSecond: 1, Every: time.Hour,
		Labels: [2]string{"rule", "route"}})
	now := time.Now()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.Skip(now, "942100", "shop")
		}
	})
}

// BenchmarkLineLimiterRefused is a refused request's line as the WAF and the
// proxy write it: Allow, told no, then Skip, with lines already pending.
func BenchmarkLineLimiterRefused(b *testing.B) {
	l := NewLineLimiter(LineLimit{Level: slog.LevelInfo, Summary: "left out", PerSecond: 1, Every: time.Hour,
		Labels: [2]string{"rule", "route"}})
	now := time.Now()
	l.Allow(now)
	l.Skip(now, "942100", "shop")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !l.Allow(now) {
				l.Skip(now, "942100", "shop")
			}
		}
	})
}
