// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package waf

import (
	"hash/fnv"
	"strconv"

	"github.com/gsoultan/gwaf/types"
)

// userRuleIDMin is the lowest rule ID an embedder may use; everything below it
// is reserved by the engine for its own ruleset.
const userRuleIDMin = uint32(types.UserMin)

// hashedRuleIDBase is where derived IDs start.
//
// It sits far above gateon's own numeric rules (which top out around 1.91M) so
// a hashed ID can never collide with one, and the span below MaxUint32 is wide
// enough that collisions between two dashboard-authored rules are negligible.
const hashedRuleIDBase = uint32(100_000_000)

// hashedRuleID derives a stable engine rule ID from a non-numeric identifier.
//
// Rules created through the dashboard get a UUID, which is not a number, but
// gwaf identifies a rule by a uint32 that appears in decisions, audit records
// and any exception written against it. Hashing is what lets those stay stable:
// the same UUID yields the same ID on every restart and on every replica, where
// assigning sequentially at load time would renumber rules whenever one was
// added and silently repoint every exception.
func hashedRuleID(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	span := ^uint32(0) - hashedRuleIDBase
	return hashedRuleIDBase + h.Sum32()%span
}

// parseUint32 parses a decimal identifier.
func parseUint32(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}
