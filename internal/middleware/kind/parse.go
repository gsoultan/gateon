// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package kind

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// Middleware configuration arrives as map[string]string from the dashboard and
// from config files, so every subpackage that builds a middleware has to turn
// those strings into numbers and flags the same way. These lived in
// package middleware, which cannot be imported from a subpackage without a
// cycle -- the factory imports the subpackages, not the other way round -- so
// they belong here with the rest of the shared primitives. ADR-0002 calls this
// out as Stage 0's purpose; the traffic stage is simply the first one to need
// them.

// RouteIDKey is the config key under which Factory.Create hands a middleware
// the route it is being built for.
//
// A constant rather than a literal retyped at each end, because the two ends
// once disagreed: a rename moved the writer to "route_id" and left three
// readers on "_route_id", so they ran with an empty route. OIDC named its state
// cookie "gateon_state_" while its callback looked for "gateon_state_<route>",
// so no login could complete, and bot-management and file-security threats
// were filed against no route. Nothing could see it: both ends were strings.
const RouteIDKey = "route_id"

// RouteStateKey is the config key under which Factory.Create hands a
// middleware the key to keep per-route state under: the route's ID, which is
// unique by construction. RouteIDKey carries the route's label -- its name, or
// its ID when it has none -- and is for what a person reads: metrics, logs,
// threat records. Names are not unique, and while state was keyed by them two
// routes called alike shared a circuit breaker and Redis cache entries.
const RouteStateKey = "route_state_key"

// MiddlewareIDKey is the config key under which Factory.Create hands a
// middleware its own ID, for state that belongs to one middleware on one
// route rather than to the route.
const MiddlewareIDKey = "middleware_id"

func ParsePositiveInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return defaultVal
	}
	return n
}
func ParseIntStrict(s string, defaultVal int) (int, error) {
	if s == "" {
		return defaultVal, nil
	}
	n, err := strconv.ParseInt(s, 10, 0)
	if err != nil {
		return defaultVal, err
	}
	return int(n), nil
}

// ParseBoolStrict reads a boolean setting. Absent is defaultVal; present and
// not a boolean strconv accepts (true, false, 1, 0, t, f, in any case) is an
// error. It used to return defaultVal for that too, unlike its int, float and
// duration siblings, so "yes" for fail_open read as false and a typo in a
// security switch read as its default, while the dashboard showed what was
// typed.
func ParseBoolStrict(s string, defaultVal bool) (bool, error) {
	if strings.TrimSpace(s) == "" {
		return defaultVal, nil
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(s))
	if err != nil {
		return defaultVal, err
	}
	return parsed, nil
}

// BoolFields reads several boolean settings from one config and keeps the
// first malformed one, so a factory can read them inline and check once.
type BoolFields struct {
	cfg map[string]string
	err error
}

// NewBoolFields reads booleans from cfg.
func NewBoolFields(cfg map[string]string) *BoolFields { return &BoolFields{cfg: cfg} }

// Get returns key's value, or defaultVal when it is absent. A malformed value
// also yields defaultVal and is reported by Err.
func (b *BoolFields) Get(key string, defaultVal bool) bool {
	v, err := ParseBoolStrict(b.cfg[key], defaultVal)
	if err != nil && b.err == nil {
		b.err = CfgError(key, b.cfg[key], err)
	}
	return v
}

// Err is the first malformed setting Get saw, naming its key and value.
func (b *BoolFields) Err() error { return b.err }

// ParseFloatStrict and ParseDurationStrict complete the strict set.
//
// The distinction all four make is between *absent* and *malformed*, and it is
// the whole reason they exist. An absent key means the operator did not set
// this, so the default is correct and silent. A malformed one means they did
// set it, and got something they did not ask for: the dashboard goes on
// displaying "ten" while the gateway runs on 0, and for a limit whose zero
// value means "no limit" -- GraphQL depth and complexity both do -- that is the
// protection switched off by a typo.
//
// strconv returns that distinction and the call sites were discarding it.

func ParseFloatStrict(s string, defaultVal float64) (float64, error) {
	if strings.TrimSpace(s) == "" {
		return defaultVal, nil
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return defaultVal, err
	}
	return f, nil
}

func ParseDurationStrict(s string, defaultVal time.Duration) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return defaultVal, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return defaultVal, err
	}
	return d, nil
}

// CfgError wraps a parse failure with the key and the value the operator wrote,
// so the message names what to go and fix rather than only what went wrong.
func CfgError(key, value string, err error) error {
	return fmt.Errorf("middleware config %q: %q is not valid: %w", key, value, err)
}

// The severity and action vocabulary every middleware reports threats in.
//
// Shared here rather than copied per subpackage on purpose. The 2026-09-19
// review found that gwaf grades rules notice/warning/error/critical while the
// correlation engine, SIEM and dashboard speak critical/high/medium/low, so
// every WAF block below critical ranked lowest and the responder never
// escalated. Two spellings of one vocabulary is how that happens; a second
// copy in a subpackage would be the same bet with a shorter fuse.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// The ActionTaken vocabulary is internal/telemetry's, because that package
// owns SecurityThreat and this one already imports it -- the reverse would be
// a cycle. Re-exported here so a middleware writing a threat record does not
// need two imports for one record, and aliased rather than copied so the
// strings cannot drift apart. A second copy is what made the severity values
// diverge for months.
const (
	ActionBlocked    = telemetry.ActionBlocked
	ActionDetected   = telemetry.ActionDetected
	ActionChallenged = telemetry.ActionChallenged
	ActionShunned    = telemetry.ActionShunned
	ActionFlagged    = telemetry.ActionFlagged
	ActionThrottled  = telemetry.ActionThrottled
)

func ParseListStrict(val string) []string {
	if val == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(val, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Header names that more than one middleware group needs.
//
// Both arrived the same way: defined in a file that a refactor stage moved,
// while a file that stayed behind was still calling them -- headerAuthorization
// in the traffic stage, headerAccept in the transform stage. Copying the string
// into each package is how two spellings of one header start, so they live here
// with the rest of the shared vocabulary.
const (
	HeaderAccept        = "Accept"
	HeaderAuthorization = "Authorization"
)
