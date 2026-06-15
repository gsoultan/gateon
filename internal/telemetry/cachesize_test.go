package telemetry

import (
	"strconv"
	"testing"
)

func TestCacheSizeFromEnv(t *testing.T) {
	const envKey = "GATEON_TELEMETRY_TEST_CACHE_SIZE"
	const cacheLabel = "test_cache"

	tests := []struct {
		name string
		set  bool
		val  string
		def  int
		want int
	}{
		{name: "Unset uses default", set: false, def: 5000, want: 5000},
		{name: "Valid override", set: true, val: "250", def: 5000, want: 250},
		{name: "Exactly minimum", set: true, val: strconv.Itoa(minCacheSize), def: 5000, want: minCacheSize},
		{name: "Below minimum falls back", set: true, val: "1", def: 5000, want: 5000},
		{name: "Zero falls back", set: true, val: "0", def: 5000, want: 5000},
		{name: "Negative falls back", set: true, val: "-100", def: 5000, want: 5000},
		{name: "Unparseable falls back", set: true, val: "abc", def: 5000, want: 5000},
		{name: "Empty falls back", set: true, val: "", def: 5000, want: 5000},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(envKey, tc.val)
			}
			got := cacheSizeFromEnv(envKey, cacheLabel, tc.def)
			if got != tc.want {
				t.Errorf("%s: cacheSizeFromEnv(%q=%q, def=%d) = %d; want %d",
					tc.name, envKey, tc.val, tc.def, got, tc.want)
			}
		})
	}
}

func TestSampleCacheOccupancyDoesNotPanic(t *testing.T) {
	// Should be safe even before any store is initialized.
	sampleCacheOccupancy()
}

func BenchmarkReputationHotPath(b *testing.B) {
	const fp = "203.0.113.7"
	ApplyRemoteReputation(fp, 42, 3, []string{"waf_block"})

	b.ReportAllocs()
	for b.Loop() {
		_ = GetReputationScore(fp)
	}
}
