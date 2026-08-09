// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package waf

import (
	"iter"
	"net"
	"net/http"
	"strings"

	"github.com/gsoultan/gwaf/rules"
)

// Resolvers are how gateon-owned signals reach a gwaf rule.
//
// gwaf analyses one request with no memory: it has no reputation store, no
// clock and no allowlist, and it never acquires one. Anything needing state,
// identity or a lookup is gateon's, and a resolver is how the *result* of that
// work becomes something a rule can match on.
//
// This replaces a genuinely dangerous pattern. Under Coraza, gateon wrote its
// reputation verdict into the request as X-Gateon-Reputation and then wrote
// SecRules that read that header back. Because the value travelled through the
// request, gateon also had to strip six X-Gateon-* headers from client input on
// every single request — miss one and a client asserts its own reputation. The
// resolver deletes the vector rather than defending it: the value never enters
// the request at all.
//
// A resolver is registered per transaction, not per WAF, because it closes over
// data specific to one request. The engine calls it only when a rule in the
// phase actually reads its name, so a resolver may be slow and should be lazy.

// Resolver names. These are part of the rule corpus's vocabulary: a rule
// selects one with types.Target{Kind: types.TargetResolved, Name: ...}.
const (
	// ResolverReputation carries gateon's verdict on the client address.
	ResolverReputation = "reputation"

	// ResolverAdminAccess carries whether this request is reaching a protected
	// administrative surface from an address that is not allowlisted.
	ResolverAdminAccess = "admin_access"

	// ResolverOrigin carries cross-header origin consistency verdicts, which a
	// rule cannot compute because it sees one value at a time.
	ResolverOrigin = "origin"
)

// Reputation buckets.
//
// gwaf ships no numeric comparison operator — there is no @ge — so reputation
// crosses the boundary as a bucket name rather than a score. That is a better
// interface anyway: the thresholds are gateon's policy, they are applied once
// where the score lives, and the rule states the condition it actually cares
// about instead of re-deriving it from a number.
const (
	// ReputationBlocked is an address an external feed has told us to refuse.
	ReputationBlocked = "blocked"

	// ReputationHostile is an address gateon's own behavioural scoring has
	// judged hostile.
	ReputationHostile = "hostile"

	// ReputationSuspect is degraded but not blocking on its own.
	ReputationSuspect = "suspect"

	// ReputationGood is the default for an address with no negative history.
	ReputationGood = "good"
)

// Admin access verdicts.
const (
	AdminAccessWPAdmin = "wp-admin"
	AdminAccessWPLogin = "wp-login"
)

// Origin verdicts.
const OriginAMPMismatch = "amp-mismatch"

// hostileScoreCeiling and suspectScoreCeiling are the thresholds the SecLang
// rules encoded as "@lt 20" and "@lt 40" against X-Gateon-Reputation. Reputation
// runs 0 (worst) to 100 (best).
const (
	hostileScoreCeiling = 20.0
	suspectScoreCeiling = 40.0
)

// ReputationResolver reports gateon's verdict on the client address.
type ReputationResolver struct {
	// Score is the behavioural reputation, 0 (worst) to 100 (best).
	Score float64

	// FeedBlocked is set when an external reputation feed says to refuse this
	// address outright.
	FeedBlocked bool
}

// Name implements rules.Resolver.
func (r ReputationResolver) Name() string { return ResolverReputation }

// Resolve implements rules.Resolver.
func (r ReputationResolver) Resolve() iter.Seq2[string, []byte] {
	return func(yield func(string, []byte) bool) {
		yield("bucket", []byte(r.bucket()))
	}
}

func (r ReputationResolver) bucket() string {
	switch {
	case r.FeedBlocked:
		return ReputationBlocked
	case r.Score < hostileScoreCeiling:
		return ReputationHostile
	case r.Score < suspectScoreCeiling:
		return ReputationSuspect
	default:
		return ReputationGood
	}
}

// AdminAccessResolver reports whether the request is reaching a protected
// administrative path from an address outside the allowlist.
//
// It replaces a SecLang rule chain whose second clause was
// "!@ipMatch %{tx.allowed_admin_ips}". Two things improve by moving it here.
// The comparison now runs against the address gateon resolved for the
// connection rather than a variable seeded earlier in the same ruleset, and the
// allowlist is parsed once at construction rather than re-split per request.
type AdminAccessResolver struct {
	// Path is the request path, already lowercased by the caller.
	Path string

	// ClientIP is the resolved peer address.
	ClientIP string

	// Allowed is the parsed allowlist. Nil means nothing is allowlisted, which
	// is the safe reading: an unset allowlist must not mean "permit everyone".
	Allowed []*net.IPNet
}

// Name implements rules.Resolver.
func (r AdminAccessResolver) Name() string { return ResolverAdminAccess }

// Resolve implements rules.Resolver.
func (r AdminAccessResolver) Resolve() iter.Seq2[string, []byte] {
	return func(yield func(string, []byte) bool) {
		verdict := r.verdict()
		if verdict == "" {
			return
		}
		yield("surface", []byte(verdict))
	}
}

func (r AdminAccessResolver) verdict() string {
	var surface string
	switch {
	case strings.Contains(r.Path, "/wp-admin"):
		surface = AdminAccessWPAdmin
	case strings.Contains(r.Path, "/wp-login.php"):
		surface = AdminAccessWPLogin
	default:
		return ""
	}
	if r.allowlisted() {
		return ""
	}
	return surface
}

func (r AdminAccessResolver) allowlisted() bool {
	ip := net.ParseIP(r.ClientIP)
	if ip == nil {
		// An address gateon could not parse is not an address on the allowlist.
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range r.Allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseAllowedAdminIPs turns configured addresses into networks. A bare address
// becomes a host route; an unparseable entry is skipped rather than silently
// widening the allowlist.
func ParseAllowedAdminIPs(entries []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			continue
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets
}

// OriginResolver reports cross-header consistency verdicts.
//
// A rule operator is handed one value and knows nothing about any other, so a
// comparison between an argument and the Host header — which is what the AMP
// source-origin rule did with a %{REQUEST_HEADERS:Host} macro — cannot be
// expressed as a rule at all. gateon does the comparison and passes the answer.
type OriginResolver struct {
	Request *http.Request
}

// Name implements rules.Resolver.
func (r OriginResolver) Name() string { return ResolverOrigin }

// Resolve implements rules.Resolver.
func (r OriginResolver) Resolve() iter.Seq2[string, []byte] {
	return func(yield func(string, []byte) bool) {
		if r.Request == nil {
			return
		}
		origin := r.Request.URL.Query().Get("__amp_source_origin")
		if origin == "" {
			return
		}
		host := r.Request.Host
		if host == "" {
			host = r.Request.Header.Get("Host")
		}
		if host == "" {
			return
		}
		if origin == "https://"+host || origin == "http://"+host {
			return
		}
		yield("amp", []byte(OriginAMPMismatch))
	}
}

var (
	_ rules.Resolver = ReputationResolver{}
	_ rules.Resolver = AdminAccessResolver{}
	_ rules.Resolver = OriginResolver{}
)
