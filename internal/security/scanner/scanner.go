// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package scanner

import (
	ahocorasick "github.com/wasilibs/go-aho-corasick"
)

// Scanner is a high-performance multi-pattern matcher using the Aho-Corasick algorithm.
type Scanner struct {
	matcher ahocorasick.AhoCorasick
}

// NewScanner creates a new scanner with the given set of patterns.
func NewScanner(patterns []string) *Scanner {
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
	})
	return &Scanner{
		matcher: builder.Build(patterns),
	}
}

// Scan returns true if any of the patterns are found in the input.
// It is optimized to stop at the first match and avoid allocations.
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
