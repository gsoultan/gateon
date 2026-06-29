// Package correlation provides a lightweight, dependency-free rules engine that
// aggregates individual security signals (the threats Gateon already records:
// brute-force attempts, exploit scans, WAF blocks, rate-limit hits, impossible
// travel, etc.) coming from the same source into higher-level Incidents. Each
// incident is annotated with the MITRE ATT&CK techniques it evidences, turning
// Gateon into a Wazuh-like sensor that emits correlated, actionable findings
// instead of a raw firehose of events.
//
// The Engine is safe for concurrent use.
package correlation

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Default tuning values for the correlation Engine.
const (
	defaultWindow         = 5 * time.Minute
	defaultMinSignals     = 3
	defaultReAlert        = time.Minute
	defaultMaxSources     = 10000
	defaultMaxPerSource   = 256
	minWindow             = 10 * time.Second
	minReAlertInterval    = 5 * time.Second
	severityWeightUnknown = 1
)

// Signal is a single detection event fed into the engine. It is intentionally
// decoupled from telemetry.SecurityThreat so the engine stays unit-testable and
// free of heavy dependencies; callers adapt their domain type into a Signal.
type Signal struct {
	Type        string
	SourceIP    string
	Fingerprint string
	Score       float64
	Severity    string
	Category    string
	RouteID     string
	RequestURI  string
	CountryCode string
	Details     string
	Time        time.Time
}

// Incident is a correlated finding aggregating multiple Signals from one source
// within the correlation window.
type Incident struct {
	ID          string      `json:"id"`
	SourceKey   string      `json:"source_key"`
	SourceIP    string      `json:"source_ip"`
	Fingerprint string      `json:"fingerprint,omitzero"`
	FirstSeen   time.Time   `json:"first_seen,omitzero"`
	LastSeen    time.Time   `json:"last_seen,omitzero"`
	Severity    string      `json:"severity"`
	Score       float64     `json:"score"`
	SignalCount int         `json:"signal_count"`
	SignalTypes []string    `json:"signal_types,omitzero"`
	Techniques  []Technique `json:"techniques,omitzero"`
	Countries   []string    `json:"countries,omitzero"`
}

// OnIncidentFunc is invoked (outside the engine lock) whenever an incident is
// opened or re-alerted. It must not block for long.
type OnIncidentFunc func(Incident)

// Config configures an Engine.
type Config struct {
	// Window is the sliding time window over which signals from one source are
	// correlated.
	Window time.Duration
	// MinSignals is the number of distinct signals within Window required to
	// raise an incident.
	MinSignals int
	// MinScore, when > 0, raises an incident once the cumulative score within
	// Window crosses it (independently of MinSignals).
	MinScore float64
	// ReAlertInterval is the minimum spacing between repeated alerts for the
	// same active source, preventing alert storms.
	ReAlertInterval time.Duration
	// MaxSources bounds the number of tracked sources (memory safety).
	MaxSources int
	// MaxSignalsPerSource bounds retained signals per source (memory safety).
	MaxSignalsPerSource int
	// OnIncident, if set, is called for each opened/re-alerted incident.
	OnIncident OnIncidentFunc
}

type sourceState struct {
	signals  []Signal
	lastSeen time.Time
	lastFire time.Time
}

// Engine correlates Signals into Incidents.
type Engine struct {
	window     time.Duration
	minSignals int
	minScore   float64
	reAlert    time.Duration
	maxSources int
	maxPerSrc  int
	onIncident OnIncidentFunc
	clock      func() time.Time
	mu         sync.Mutex
	sources    map[string]*sourceState
}

// New builds an Engine from cfg, applying safe defaults and floors.
func New(cfg Config) *Engine {
	window := cfg.Window
	switch {
	case window <= 0:
		window = defaultWindow
	case window < minWindow:
		window = minWindow
	}

	reAlert := cfg.ReAlertInterval
	switch {
	case reAlert <= 0:
		reAlert = defaultReAlert
	case reAlert < minReAlertInterval:
		reAlert = minReAlertInterval
	}

	minSignals := cfg.MinSignals
	if minSignals <= 0 {
		minSignals = defaultMinSignals
	}
	maxSources := cfg.MaxSources
	if maxSources <= 0 {
		maxSources = defaultMaxSources
	}
	maxPerSrc := cfg.MaxSignalsPerSource
	if maxPerSrc <= 0 {
		maxPerSrc = defaultMaxPerSource
	}

	return &Engine{
		window:     window,
		minSignals: minSignals,
		minScore:   cfg.MinScore,
		reAlert:    reAlert,
		maxSources: maxSources,
		maxPerSrc:  maxPerSrc,
		onIncident: cfg.OnIncident,
		clock:      time.Now,
		sources:    make(map[string]*sourceState),
	}
}

// sourceKey prefers the (more stable) fingerprint, falling back to source IP.
func sourceKey(s Signal) string {
	if s.Fingerprint != "" {
		return s.Fingerprint
	}
	return s.SourceIP
}

// Observe ingests a signal and, if it crosses the correlation threshold,
// returns the raised incident. It also invokes OnIncident (outside the lock).
func (e *Engine) Observe(s Signal) (Incident, bool) {
	if s.Time.IsZero() {
		s.Time = e.clock()
	}
	key := sourceKey(s)
	if key == "" {
		return Incident{}, false
	}

	e.mu.Lock()
	inc, fired := e.observeLocked(key, s)
	e.mu.Unlock()

	if fired && e.onIncident != nil {
		e.onIncident(inc)
	}
	return inc, fired
}

// observeLocked performs the stateful part of Observe. Caller holds e.mu.
func (e *Engine) observeLocked(key string, s Signal) (Incident, bool) {
	now := e.clock()
	st := e.sources[key]
	if st == nil {
		e.evictIfFullLocked()
		st = &sourceState{}
		e.sources[key] = st
	}

	cutoff := now.Add(-e.window)
	st.signals = pruneOld(st.signals, cutoff)
	st.signals = append(st.signals, s)
	if overflow := len(st.signals) - e.maxPerSrc; overflow > 0 {
		st.signals = st.signals[overflow:]
	}
	st.lastSeen = now

	if !e.thresholdMet(st.signals) {
		return Incident{}, false
	}
	if !st.lastFire.IsZero() && now.Sub(st.lastFire) < e.reAlert {
		return Incident{}, false
	}
	st.lastFire = now
	return e.buildIncident(key, st.signals), true
}

// thresholdMet reports whether the retained signals satisfy either the count or
// (when enabled) the cumulative-score threshold.
func (e *Engine) thresholdMet(signals []Signal) bool {
	if len(signals) >= e.minSignals {
		return true
	}
	if e.minScore > 0 {
		var total float64
		for _, sig := range signals {
			total += sig.Score
		}
		if total >= e.minScore {
			return true
		}
	}
	return false
}

// buildIncident aggregates the windowed signals into an Incident.
func (e *Engine) buildIncident(key string, signals []Signal) Incident {
	var (
		score      float64
		typeSet    = map[string]struct{}{}
		techSet    = map[string]Technique{}
		countrySet = map[string]struct{}{}
		topSev     = "low"
	)
	first := signals[0].Time
	last := signals[0].Time
	fingerprint := ""
	sourceIP := ""

	for _, sig := range signals {
		score += sig.Score
		typeSet[sig.Type] = struct{}{}
		for _, t := range Techniques(sig.Type) {
			techSet[t.ID] = t
		}
		if sig.CountryCode != "" {
			countrySet[sig.CountryCode] = struct{}{}
		}
		if sig.Time.Before(first) {
			first = sig.Time
		}
		if sig.Time.After(last) {
			last = sig.Time
		}
		if severityRank(sig.Severity) > severityRank(topSev) {
			topSev = normalizeSeverity(sig.Severity)
		}
		if fingerprint == "" && sig.Fingerprint != "" {
			fingerprint = sig.Fingerprint
		}
		if sourceIP == "" && sig.SourceIP != "" {
			sourceIP = sig.SourceIP
		}
	}

	return Incident{
		ID:          uuid.NewString(),
		SourceKey:   key,
		SourceIP:    sourceIP,
		Fingerprint: fingerprint,
		FirstSeen:   first,
		LastSeen:    last,
		Severity:    topSev,
		Score:       score,
		SignalCount: len(signals),
		SignalTypes: sortedKeys(typeSet),
		Techniques:  sortedTechniques(techSet),
		Countries:   sortedKeys(countrySet),
	}
}

// evictIfFullLocked drops the least-recently-active source when at capacity.
func (e *Engine) evictIfFullLocked() {
	if len(e.sources) < e.maxSources {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, st := range e.sources {
		if oldestKey == "" || st.lastSeen.Before(oldest) {
			oldestKey = k
			oldest = st.lastSeen
		}
	}
	if oldestKey != "" {
		delete(e.sources, oldestKey)
	}
}

// GC removes sources whose most recent signal predates the correlation window.
// It is safe to call periodically to reclaim memory for idle sources.
func (e *Engine) GC() {
	cutoff := e.clock().Add(-e.window)
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, st := range e.sources {
		if st.lastSeen.Before(cutoff) {
			delete(e.sources, k)
		}
	}
}

// TrackedSources returns the number of currently tracked sources.
func (e *Engine) TrackedSources() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.sources)
}

// Run consumes signals from in and periodically GCs idle sources until ctx is
// cancelled. It blocks and is intended to run in its own goroutine.
func (e *Engine) Run(ctx context.Context, in <-chan Signal) {
	ticker := time.NewTicker(e.window)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case sig, ok := <-in:
			if !ok {
				return
			}
			e.Observe(sig)
		case <-ticker.C:
			e.GC()
		}
	}
}

// pruneOld drops signals with a timestamp before cutoff, preserving order.
func pruneOld(signals []Signal, cutoff time.Time) []Signal {
	idx := 0
	for idx < len(signals) && signals[idx].Time.Before(cutoff) {
		idx++
	}
	if idx == 0 {
		return signals
	}
	return append(signals[:0], signals[idx:]...)
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedTechniques(set map[string]Technique) []Technique {
	if len(set) == 0 {
		return []Technique{}
	}
	out := make([]Technique, 0, len(set))
	for _, t := range set {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func normalizeSeverity(s string) string {
	switch s {
	case "critical", "high", "medium", "low":
		return s
	default:
		return "low"
	}
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return severityWeightUnknown
	}
}
