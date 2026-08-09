// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package waf

import (
	"bytes"
	"strings"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// gwaf's core ships four operators — Contains, ContainsAny, Equals and
// HasPrefix — plus a regex tier in rules/op/rx, which is where gateon's @rx
// corpus goes. What remains here are the two shapes none of them express.
//
// Both are stateless after construction and safe for concurrent use: one
// operator instance is shared by every transaction evaluating its rule.

// Present matches any value at all.
//
// It is the @rx ".*" replacement, used for rules that key off a header or
// argument merely existing — a vendor-specific header that only an exploit
// sends, for instance. It is meaningful only on a keyed target: the engine
// evaluates it once per value present under that key, so an absent header
// produces no evaluation and no match.
type Present struct{ name string }

// NewPresent returns a Present operator labelled name.
func NewPresent(name string) *Present { return &Present{name: name} }

// Name implements rules.Operator.
func (o *Present) Name() string { return "present:" + o.name }

// Eval implements rules.Operator.
func (o *Present) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	return rules.WholeValue(value), true
}

// Literals implements rules.Operator.
//
// Presence cannot be prefiltered by content: there is no byte sequence the
// value must contain. Returning false here is the honest answer and makes the
// rule show up in the compile report's Unconditional list, which is where a
// cost like this belongs — visible at build time rather than in a latency
// graph. Rules using it must be narrowly keyed to stay cheap.
func (o *Present) Literals() ([]string, bool) { return nil, false }

// Cost implements rules.Operator.
func (o *Present) Cost() types.Fuel { return types.CostLiteralMatch }

// SegmentCount matches values containing at least min occurrences of sep.
//
// It replaces the `(/[^/]+){15,}` style of rule, which expresses "too many path
// segments" as a regex that the engine must run in full. Counting bytes stops
// at the threshold and allocates nothing.
type SegmentCount struct {
	name string
	sep  byte
	min  int
}

// NewSegmentCount returns an operator matching values with at least min
// occurrences of sep.
func NewSegmentCount(name string, sep byte, minCount int) *SegmentCount {
	return &SegmentCount{name: name, sep: sep, min: minCount}
}

// Name implements rules.Operator.
func (o *SegmentCount) Name() string { return "segments:" + o.name }

// Eval implements rules.Operator.
func (o *SegmentCount) Eval(_ *rules.EvalContext, value []byte) (rules.Match, bool) {
	if bytes.Count(value, []byte{o.sep}) < o.min {
		return rules.Match{}, false
	}
	return rules.WholeValue(value), true
}

// Literals implements rules.Operator.
//
// The separator alone is a genuine requirement — a value with fewer than min
// occurrences of it cannot match — so the prefilter can use it. It is a weak
// filter for a byte as common as '/', but it is a true one.
func (o *SegmentCount) Literals() ([]string, bool) {
	if o.min <= 0 {
		return nil, false
	}
	return []string{string(o.sep)}, true
}

// Cost implements rules.Operator.
func (o *SegmentCount) Cost() types.Fuel { return types.CostLiteralMatch }

// KeySuffix restricts an operator to values whose key ends in a suffix.
//
// A rule target selects a key by exact match, which is the right default but
// cannot express a convention. Nested structures are where that bites: gwaf
// records a JSON field as its full path, so "the password field, wherever it
// appears" is "user.password" and "account.owner.password" and any other
// prefix an API happens to use.
//
// EvalContext carries the key precisely so an operator can make this kind of
// decision, which is why this is a wrapper rather than a fork of each rule.
//
// It is deliberately not how uploaded file names are selected: those have
// their own target (types.TargetFileNames), because a file name is a different
// kind of value rather than an argument with a naming convention.
type KeySuffix struct {
	suffix string
	inner  rules.Operator
}

// ScopeToKeySuffix returns inner, restricted to values whose key ends in suffix.
func ScopeToKeySuffix(suffix string, inner rules.Operator) *KeySuffix {
	return &KeySuffix{suffix: suffix, inner: inner}
}

// Name implements rules.Operator.
func (o *KeySuffix) Name() string { return "key~" + o.suffix + ":" + o.inner.Name() }

// Eval implements rules.Operator.
func (o *KeySuffix) Eval(ctx *rules.EvalContext, value []byte) (rules.Match, bool) {
	if ctx == nil || !strings.HasSuffix(ctx.Key, o.suffix) {
		return rules.Match{}, false
	}
	return o.inner.Eval(ctx, value)
}

// Literals implements rules.Operator.
//
// Delegating is sound in the direction that matters: this operator matches a
// strict subset of what inner matches, so a literal inner genuinely requires is
// still genuinely required here. Narrowing a rule can never invalidate a
// required-literal claim, only strengthen it.
func (o *KeySuffix) Literals() ([]string, bool) { return o.inner.Literals() }

// Cost implements rules.Operator.
func (o *KeySuffix) Cost() types.Fuel { return o.inner.Cost() }

// Compile-time proof that each operator satisfies the interface. Without these
// a signature drift in gwaf would surface as a confusing error inside a rule
// literal rather than here.
var (
	_ rules.Operator = (*Present)(nil)
	_ rules.Operator = (*SegmentCount)(nil)
	_ rules.Operator = (*KeySuffix)(nil)
)
