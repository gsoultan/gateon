// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package scanner

import (
	ahocorasick "github.com/wasilibs/go-aho-corasick"
)

// Scanner is a high-performance multi-pattern matcher using the Aho-Corasick algorithm.
type Scanner struct {
	matcher ahocorasick.AhoCorasick
}

// NewScanner creates a new scanner with the given set of patterns.
//
// Empty patterns are dropped. An empty needle matches at every position, so a
// single one among real patterns makes Scan answer true for all input --
// turning a detector into something that flags every request while still
// looking configured. The pattern lists are compile-time constants today, and
// this keeps that from becoming a trap if they ever come from config.
func NewScanner(patterns []string) *Scanner {
	kept := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if p != "" {
			kept = append(kept, p)
		}
	}
	patterns = kept

	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
	})
	return &Scanner{
		matcher: builder.Build(patterns),
	}
}

// Scan returns true if any of the patterns are found in the input. It stops at
// the first match rather than collecting them.
//
// It is not allocation-free, whatever this comment used to say: Iter allocates
// its iterator, measured at three allocations per call, and the library exposes
// no single-match entry point that avoids them. Stating that plainly matters
// because this runs on the request path and the old claim invited callers to
// treat it as free. ScanDoesNotRegress pins the current cost.
func (s *Scanner) Scan(input string) bool {
	return s.matcher.Iter(input).Next() != nil
}

// FindAll returns all patterns found in the input.
func (s *Scanner) FindAll(input string) []string {
	matches := s.matcher.FindAll(input)
	if len(matches) == 0 {
		return nil
	}
	// Note: The library FindAll might return match objects.
	// Depending on the version, we might need to extract the pattern index.
	// We'll return the matched substrings for simplicity.
	results := make([]string, 0, len(matches))
	for _, m := range matches {
		results = append(results, input[m.Start():m.End()])
	}
	return results
}
