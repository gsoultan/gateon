// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package waf

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/rules/op/rx"
	"github.com/gsoultan/gwaf/rules/transform"
	"github.com/gsoultan/gwaf/types"
)

// Definition is the stored, authorable form of a WAF rule.
//
// It replaces the SecLang text that used to live in waf_rules.directive. The
// reason for a data format rather than a language is that a language needs a
// parser, and a parser that accepts a rule it then compiles to something
// slightly different is how a rule silently stops meaning what its author
// intended. Every field here maps to exactly one field of a gwaf rule, and
// anything that does not map is a validation error at save time rather than a
// surprise at request time.
//
// It is JSON because it is edited in the dashboard and stored in a column.
type Definition struct {
	// Phase is when the rule runs: request_headers, request_body,
	// response_headers or response_body.
	Phase string `json:"phase"`

	// Targets are the collections to inspect, each "kind" or "kind:name".
	Targets []string `json:"targets"`

	// Transforms normalize each value before the operator sees it, in order.
	Transforms []string `json:"transforms,omitempty"`

	// Operator decides whether a transformed value matches.
	Operator OperatorDef `json:"operator"`

	// Action is block, score or log. Empty means block.
	Action string `json:"action,omitempty"`

	// Status is the HTTP status for a block. Zero uses the policy default.
	Status int `json:"status,omitempty"`

	// Severity is notice, warning, error or critical.
	Severity string `json:"severity"`

	// Confidence is heuristic, low, medium, high or certain. It decides
	// whether the rule survives the configured paranoia level.
	Confidence string `json:"confidence"`

	// Msg is the human-readable description shown in decisions and audit output.
	Msg string `json:"msg"`

	// Tags group the rule for policy selection and exceptions.
	Tags []string `json:"tags,omitempty"`
}

// OperatorDef names an operator and its argument.
type OperatorDef struct {
	// Kind is regex, contains, contains_any, equals, prefix, present or
	// segment_count.
	Kind string `json:"kind"`

	// Pattern is the argument for regex, contains, equals and prefix.
	Pattern string `json:"pattern,omitempty"`

	// Values is the argument for contains_any.
	Values []string `json:"values,omitempty"`

	// Min is the threshold for segment_count.
	Min int `json:"min,omitempty"`

	// Separator is the delimiter for segment_count. Defaults to "/".
	Separator string `json:"separator,omitempty"`

	// KeySuffix optionally restricts the operator to values whose key ends in
	// this suffix, for conventions in nested structures — a JSON field named
	// "password" at any path, for instance. Uploaded file names have their own
	// target and do not need it.
	KeySuffix string `json:"key_suffix,omitempty"`
}

// Compile turns a stored definition into a gwaf rule.
//
// Every failure names the field and the accepted values. An operator editing a
// rule in the dashboard gets the same message the API returns, and neither is a
// generic "invalid rule".
func (d Definition) Compile(id uint32) (rules.Rule, error) {
	phase, err := parsePhase(d.Phase)
	if err != nil {
		return rules.Rule{}, err
	}
	targets, err := parseTargets(d.Targets)
	if err != nil {
		return rules.Rule{}, err
	}
	xforms, err := parseTransforms(d.Transforms)
	if err != nil {
		return rules.Rule{}, err
	}
	operator, err := d.Operator.compile()
	if err != nil {
		return rules.Rule{}, err
	}
	severity, confidence, action, err := d.parseVerdict()
	if err != nil {
		return rules.Rule{}, err
	}

	return rules.Rule{
		ID:         types.RuleID(id),
		Phase:      phase,
		Targets:    targets,
		Transforms: xforms,
		Op:         operator,
		Actions:    []rules.Action{action},
		Severity:   severity,
		Confidence: confidence,
		Msg:        d.Msg,
		Tags:       d.Tags,
	}, nil
}

// parseVerdict reads the fields that describe what a match means and what to
// do about it.
func (d Definition) parseVerdict() (types.Severity, types.Confidence, rules.Action, error) {
	severity, ok := types.ParseSeverity(d.Severity)
	if !ok {
		return 0, 0, nil, fmt.Errorf("severity %q: want notice, warning, error or critical", d.Severity)
	}
	confidence, ok := types.ParseConfidence(d.Confidence)
	if !ok {
		return 0, 0, nil, fmt.Errorf("confidence %q: want heuristic, low, medium, high or certain", d.Confidence)
	}
	action, err := parseAction(d.Action, d.Status)
	if err != nil {
		return 0, 0, nil, err
	}
	if strings.TrimSpace(d.Msg) == "" {
		return 0, 0, nil, fmt.Errorf("msg is required: a block with no message cannot be explained")
	}
	return severity, confidence, action, nil
}

func parsePhase(s string) (types.Phase, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "request_headers", "":
		return types.PhaseRequestHeaders, nil
	case "request_body":
		return types.PhaseRequestBody, nil
	case "response_headers":
		return types.PhaseResponseHeaders, nil
	case "response_body":
		return types.PhaseResponseBody, nil
	default:
		return 0, fmt.Errorf("phase %q: want request_headers, request_body, response_headers or response_body", s)
	}
}

// targetKinds maps the stored name of a collection to its kind. The names are
// the SecLang collections an operator already knows, lowercased.
var targetKinds = map[string]types.TargetKind{
	"method":        types.TargetRequestMethod,
	"uri":           types.TargetRequestURI,
	"path":          types.TargetRequestPath,
	"protocol":      types.TargetRequestProtocol,
	"headers":       types.TargetRequestHeaders,
	"header_names":  types.TargetRequestHeaderNames,
	"args":          types.TargetArgs,
	"arg_names":     types.TargetArgNames,
	"args_get":      types.TargetArgsGet,
	"args_post":     types.TargetArgsPost,
	"body":          types.TargetRequestBody,
	"cookies":       types.TargetRequestCookies,
	"cookie_names":  types.TargetRequestCookieNames,
	"remote_addr":   types.TargetRemoteAddr,
	"args_joined":   types.TargetArgsJoined,
	"resolved":      types.TargetResolved,
	"resp_status":   types.TargetResponseStatus,
	"resp_headers":  types.TargetResponseHeaders,
	"resp_hdr_name": types.TargetResponseHeaderNames,
	"resp_body":     types.TargetResponseBody,
}

func parseTargets(ss []string) ([]types.Target, error) {
	if len(ss) == 0 {
		return nil, fmt.Errorf("targets: a rule with none inspects nothing and can never match")
	}
	out := make([]types.Target, 0, len(ss))
	for _, s := range ss {
		kindName, name, _ := strings.Cut(strings.TrimSpace(s), ":")
		kind, ok := targetKinds[strings.ToLower(kindName)]
		if !ok {
			return nil, fmt.Errorf("target %q: unknown collection %q", s, kindName)
		}
		out = append(out, types.Target{Kind: kind, Name: name})
	}
	return out, nil
}

var transformsByName = map[string]rules.Transform{
	"lowercase":           transform.Lowercase,
	"urldecode":           transform.URLDecode,
	"remove_whitespace":   transform.RemoveWhitespace,
	"compress_whitespace": transform.CompressWhitespace,
	"normalize_path":      transform.NormalizePath,
}

func parseTransforms(ss []string) ([]rules.Transform, error) {
	if len(ss) == 0 {
		return nil, nil
	}
	out := make([]rules.Transform, 0, len(ss))
	for _, s := range ss {
		t, ok := transformsByName[strings.ToLower(strings.TrimSpace(s))]
		if !ok {
			return nil, fmt.Errorf("transform %q: want lowercase, urldecode, remove_whitespace, compress_whitespace or normalize_path", s)
		}
		out = append(out, t)
	}
	return out, nil
}

func parseAction(name string, status int) (rules.Action, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "block", "":
		if status != 0 {
			return rules.BlockWithStatus(status), nil
		}
		return rules.Block, nil
	case "score":
		return rules.Score, nil
	case "log":
		return rules.Log, nil
	default:
		// "allow" is deliberately absent. An over-broad allow silently disables
		// protection for everything it covers, and an exception expresses the
		// same intent with a stated scope.
		return nil, fmt.Errorf("action %q: want block, score or log", name)
	}
}

func (o OperatorDef) compile() (rules.Operator, error) {
	inner, err := o.compileInner()
	if err != nil {
		return nil, err
	}
	if o.KeySuffix != "" {
		return ScopeToKeySuffix(o.KeySuffix, inner), nil
	}
	return inner, nil
}

func (o OperatorDef) compileInner() (rules.Operator, error) {
	switch strings.ToLower(strings.TrimSpace(o.Kind)) {
	case "regex":
		if o.Pattern == "" {
			return nil, fmt.Errorf("operator regex: pattern is required")
		}
		r, err := rx.New(o.Pattern)
		if err != nil {
			// RE2 rejects backreferences and lookaround. Saying so is more
			// useful than "invalid pattern", because those are exactly what a
			// rule copied from a PCRE-based ruleset will contain.
			return nil, fmt.Errorf("operator regex: %w (RE2 has no backreferences or lookaround)", err)
		}
		return r, nil
	case "contains":
		if o.Pattern == "" {
			return nil, fmt.Errorf("operator contains: pattern is required")
		}
		return op.Contains(o.Pattern), nil
	case "contains_any":
		if len(o.Values) == 0 {
			return nil, fmt.Errorf("operator contains_any: values are required")
		}
		return op.ContainsAny(o.Values...), nil
	case "equals":
		return op.Equals(o.Pattern), nil
	case "prefix":
		if o.Pattern == "" {
			return nil, fmt.Errorf("operator prefix: pattern is required")
		}
		return op.HasPrefix(o.Pattern), nil
	default:
		return o.compileCounting()
	}
}

// compileCounting handles the operators gateon supplies rather than gwaf.
func (o OperatorDef) compileCounting() (rules.Operator, error) {
	switch strings.ToLower(strings.TrimSpace(o.Kind)) {
	case "present":
		return NewPresent(o.Pattern), nil
	case "segment_count":
		if o.Min <= 0 {
			return nil, fmt.Errorf("operator segment_count: min must be positive")
		}
		sep := byte('/')
		if o.Separator != "" {
			sep = o.Separator[0]
		}
		return NewSegmentCount(o.Pattern, sep, o.Min), nil
	default:
		return nil, fmt.Errorf("operator kind %q: want regex, contains, contains_any, equals, prefix, present or segment_count", o.Kind)
	}
}

// Validate reports whether the definition compiles, without needing an ID.
func (d Definition) Validate() error {
	_, err := d.Compile(uint32(types.UserMin))
	return err
}

// ParseDefinition decodes a stored definition.
func ParseDefinition(raw string) (Definition, error) {
	var d Definition
	dec := json.NewDecoder(strings.NewReader(raw))
	// An unknown field is almost always a typo in a hand-edited rule, and
	// accepting it silently would mean the rule does something other than what
	// its author wrote.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Definition{}, fmt.Errorf("rule definition: %w", err)
	}
	return d, nil
}
