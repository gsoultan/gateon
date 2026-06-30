package api

import (
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// IPStats holds aggregated metrics for a specific source IP.
type IPStats struct {
	TotalRequests int
	Error4xx      int
	Error401      int
	Error403      int
	Error404      int
	Error5xx      int
	TotalDuration float64
	LastSeen      time.Time
	UniquePaths   map[string]struct{}
	CountryCode   string
	UserAgents    map[string]struct{}
	Methods       map[string]int
	Referers      map[string]int
	BurstCount    int            // Requests in the peak 10-second window
	JA3s          map[string]int // Track JA3 fingerprints per IP
	JA4s          map[string]int // Track JA4 fingerprints per IP
	PathErrors    map[string]int // Track 401/403 errors per path
	HeaderAnomaly int            // Count of requests with suspicious header combinations
	LastTrace     *telemetry.TraceRecord

	// Advanced Behavioral Signals
	IATSum        float64   // Sum of durations between requests (ms)
	IATSumSq      float64   // Sum of squares of durations (ms^2)
	IATCount      int       // Number of inter-arrival intervals
	LastRequestAt time.Time // Time of previous request for IAT calculation
	LastPathHash  uint64    // Previous path hash
	PrevPathHash  uint64    // Path hash before LastPathHash
}
