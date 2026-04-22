package api

import (
	"time"
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
	BurstCount    int // Requests in the peak 10-second window
}
