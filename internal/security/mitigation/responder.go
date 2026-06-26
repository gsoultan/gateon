// Package mitigation turns correlated security incidents into graduated,
// confidence-aware mitigation actions. It is the missing link between detection
// (the correlation engine, which has the best cross-signal view of a source) and
// enforcement (reputation degradation + eBPF shunning).
//
// The design deliberately favours reversible, escalating responses over a binary
// block so that legitimate heavy traffic is not knocked offline by a single noisy
// signal:
//
//   - A single legitimate high-traffic client typically trips ONE signal type
//     repeatedly (e.g. rate_limit). A real attack trips DIVERSE signal types
//     (scan + exploit + brute-force…). Active mitigation therefore requires a
//     minimum number of DISTINCT signal types, not just a raw signal count.
//   - An allowlist (trusted CIDRs) and private/loopback addresses are never
//     actively mitigated.
//   - Reputation degradation is graduated and self-healing: it tightens the WAF's
//     adaptive anomaly threshold and hardens proof-of-work challenges for the
//     offending source, then recovers over time if the behaviour stops.
//   - Hard eBPF shunning is reserved for high-confidence critical incidents and
//     is opt-in (AutoShun), since it is the least forgiving response.
package mitigation

import (
	"net/netip"
	"strings"

	"github.com/gsoultan/gateon/internal/security/correlation"
)

// Action is the mitigation applied to an incident's source.
type Action string

const (
	// ActionNone means the responder is disabled or the source is allowlisted.
	ActionNone Action = "none"
	// ActionFlag records the incident without touching the source (low confidence).
	ActionFlag Action = "flagged"
	// ActionDegrade applies a moderate reputation penalty (tightens WAF/PoW).
	ActionDegrade Action = "reputation_degraded"
	// ActionRestrict applies a heavy reputation penalty (near-block via WAF).
	ActionRestrict Action = "restricted"
	// ActionShun hard-blocks the source IP at the XDP/eBPF layer.
	ActionShun Action = "shunned"
)

// Shunner hard-blocks a source IP (satisfied by *ebpf.Holder / ebpf.Manager).
type Shunner interface {
	ShunIP(ip string) error
}

// Config tunes the responder. Zero value is usable via Normalize().
type Config struct {
	// Enabled gates all active mitigation. When false, every incident is flagged
	// only (recorded, never enforced).
	Enabled bool
	// AutoShun enables hard eBPF shunning for high-confidence critical incidents.
	// Off by default: a hard block is the least forgiving response and a false
	// positive there is the most damaging.
	AutoShun bool
	// Allowlist sources that must never be actively mitigated.
	Allowlist []netip.Prefix
	// MinDistinctSignalsForActive is the minimum number of distinct signal types
	// required before any reputation degradation is applied (false-positive guard
	// against single-signal heavy traffic). Default 2.
	MinDistinctSignalsForActive int
	// MinDistinctSignalsForShun is the minimum distinct signal types required for a
	// hard shun. Default 3.
	MinDistinctSignalsForShun int
	// DegradePenalty / RestrictPenalty are the reputation penalties applied for the
	// degrade / restrict tiers. Defaults 25 / 60.
	DegradePenalty  float64
	RestrictPenalty float64
}

// Normalize fills zero-value fields with safe defaults.
func (c Config) Normalize() Config {
	if c.MinDistinctSignalsForActive <= 0 {
		c.MinDistinctSignalsForActive = 2
	}
	if c.MinDistinctSignalsForShun <= 0 {
		c.MinDistinctSignalsForShun = 3
	}
	if c.DegradePenalty <= 0 {
		c.DegradePenalty = 25
	}
	if c.RestrictPenalty <= 0 {
		c.RestrictPenalty = 60
	}
	return c
}

// Responder applies graduated mitigation to incidents.
type Responder struct {
	cfg     Config
	shun    Shunner
	degrade func(fingerprint string, penalty float64, reason string)
	mark    func(ip, reason string)
	log     func(action Action, inc correlation.Incident, reason string)
}

// Deps are the injected effectors, kept as functions/interfaces so the responder
// is unit-testable without telemetry/eBPF.
type Deps struct {
	Shun    Shunner                                                  // may be nil (no shunning available)
	Degrade func(fingerprint string, penalty float64, reason string) // required for degrade/restrict
	Mark    func(ip, reason string)                                  // optional: record mitigated IP
	Log     func(action Action, inc correlation.Incident, reason string)
}

// New builds a responder from cfg and deps.
func New(cfg Config, deps Deps) *Responder {
	return &Responder{
		cfg:     cfg.Normalize(),
		shun:    deps.Shun,
		degrade: deps.Degrade,
		mark:    deps.Mark,
		log:     deps.Log,
	}
}

// Handle decides and applies the mitigation for an incident, returning the action
// taken. It is safe to call from the incident callback.
func (r *Responder) Handle(inc correlation.Incident) Action {
	if !r.cfg.Enabled {
		return ActionNone
	}
	if r.isAllowlisted(inc.SourceIP) {
		r.emit(ActionNone, inc, "source allowlisted")
		return ActionNone
	}

	distinct := distinctSignalTypes(inc.SignalTypes)
	sev := strings.ToLower(strings.TrimSpace(inc.Severity))

	// Single-signal-type incidents (e.g. one heavy client tripping only
	// rate_limit) are flagged but never actively mitigated — the core guard that
	// keeps legitimate bursty traffic online.
	if distinct < r.cfg.MinDistinctSignalsForActive {
		r.emit(ActionFlag, inc, "insufficient signal diversity for active mitigation")
		return ActionFlag
	}

	switch sev {
	case "critical":
		if r.cfg.AutoShun && r.shun != nil && inc.SourceIP != "" &&
			distinct >= r.cfg.MinDistinctSignalsForShun {
			if err := r.shun.ShunIP(inc.SourceIP); err == nil {
				r.degradeRep(inc, r.cfg.RestrictPenalty)
				if r.mark != nil {
					r.mark(inc.SourceIP, "correlated critical incident: "+strings.Join(inc.SignalTypes, ","))
				}
				r.emit(ActionShun, inc, "critical multi-signal incident")
				return ActionShun
			}
			// Shun failed (no privilege / no manager): fall through to restrict.
		}
		r.degradeRep(inc, r.cfg.RestrictPenalty)
		r.emit(ActionRestrict, inc, "critical incident")
		return ActionRestrict
	case "high":
		r.degradeRep(inc, r.cfg.RestrictPenalty)
		r.emit(ActionRestrict, inc, "high-severity incident")
		return ActionRestrict
	case "medium":
		r.degradeRep(inc, r.cfg.DegradePenalty)
		r.emit(ActionDegrade, inc, "medium-severity incident")
		return ActionDegrade
	default:
		r.emit(ActionFlag, inc, "low-severity incident")
		return ActionFlag
	}
}

func (r *Responder) degradeRep(inc correlation.Incident, penalty float64) {
	if r.degrade == nil || inc.Fingerprint == "" {
		return
	}
	r.degrade(inc.Fingerprint, penalty, "correlated incident: "+strings.Join(inc.SignalTypes, ","))
}

func (r *Responder) emit(a Action, inc correlation.Incident, reason string) {
	if r.log != nil {
		r.log(a, inc, reason)
	}
}

func (r *Responder) isAllowlisted(ip string) bool {
	if ip == "" {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	// Never mitigate loopback/private/link-local sources — these are operators,
	// health checks, sidecars, and internal mesh traffic.
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range r.cfg.Allowlist {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func distinctSignalTypes(types []string) int {
	if len(types) == 0 {
		return 0
	}
	seen := make(map[string]struct{}, len(types))
	for _, t := range types {
		if t = strings.TrimSpace(t); t != "" {
			seen[t] = struct{}{}
		}
	}
	return len(seen)
}

// ParseAllowlist parses a comma-separated list of CIDRs / bare IPs into prefixes,
// skipping invalid entries. Bare IPs become /32 (v4) or /128 (v6).
func ParseAllowlist(raw string) []netip.Prefix {
	var out []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p)
			continue
		}
		if addr, err := netip.ParseAddr(part); err == nil {
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return out
}
