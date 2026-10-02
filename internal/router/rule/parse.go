// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package rule

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// maxDepth bounds how deeply parentheses nest. A rule is operator input as
// long as the API body allows, and both parsing and evaluation recurse once
// per level; a run of '!' does not count, because it is folded into one
// negation as it is read.
const maxDepth = 32

// parser reads one rule left to right. Every error it returns names the
// character where reading stopped.
type parser struct {
	src   string
	pos   int
	depth int
}

// Parse reads a whole rule. Anything it cannot read -- an unknown condition, a
// value or parenthesis left open, a regular expression that does not compile,
// an empty value, text after the last condition -- is an *Error, and no part
// of the rule is used.
func Parse(src string) (*Expr, error) {
	p := &parser{src: src}
	p.skipSpace()
	if p.pos == len(src) {
		return nil, p.errAt(0, "the rule is empty; a route needs at least one condition, such as PathPrefix(`/`)")
	}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos < len(src) {
		return nil, p.unexpected("conditions are joined with && or ||")
	}
	return &Expr{root: root}, nil
}

func (p *parser) parseOr() (node, error) {
	return p.parseList(opOr, "||", p.parseAnd)
}

func (p *parser) parseAnd() (node, error) {
	return p.parseList(opAnd, "&&", p.parseUnary)
}

// parseList reads one or more operands joined by op. A single operand is
// returned as itself.
func (p *parser) parseList(k kind, op string, operand func() (node, error)) (node, error) {
	first, err := operand()
	if err != nil {
		return node{}, err
	}
	parts := []node{first}
	for p.consume(op) {
		next, err := operand()
		if err != nil {
			return node{}, err
		}
		parts = append(parts, next)
	}
	if len(parts) == 1 {
		return first, nil
	}
	return node{kind: k, children: parts}, nil
}

// parseUnary folds a run of '!' into at most one negation, in a loop: a run is
// as long as the API body allows, and recursing once per '!' exhausted the
// goroutine stack, which is fatal rather than a recoverable panic.
func (p *parser) parseUnary() (node, error) {
	negated := false
	for p.skipSpace(); p.pos < len(p.src) && p.src[p.pos] == '!'; p.skipSpace() {
		negated = !negated
		p.pos++
	}
	n, err := p.parsePrimary()
	if err != nil || !negated {
		return n, err
	}
	return node{kind: opNot, children: []node{n}}, nil
}

func (p *parser) parsePrimary() (node, error) {
	p.skipSpace()
	if p.pos == len(p.src) {
		return node{}, p.errAt(p.pos, "expected a condition, such as Host(`example.com`), but the rule ends here")
	}
	if p.src[p.pos] != '(' {
		return p.parseCondition()
	}
	open := p.pos
	if p.depth == maxDepth {
		return node{}, p.errAt(open, fmt.Sprintf("parentheses nest more than %d deep", maxDepth))
	}
	p.depth++
	p.pos++
	n, err := p.parseOr()
	p.depth--
	if err != nil {
		return node{}, err
	}
	p.skipSpace()
	if !p.consumeByte(')') {
		return node{}, p.unexpected(fmt.Sprintf("expected ) to close the parenthesis at character %d", p.charPos(open)))
	}
	return n, nil
}

// parseCondition reads name(values) and builds the condition it names.
func (p *parser) parseCondition() (node, error) {
	start := p.pos
	name := p.ident()
	if name == "" {
		return node{}, p.unexpected("expected a condition, such as Host(`example.com`)")
	}
	if !isCondition(name) {
		return node{}, p.errAt(start, unknownCondition(name))
	}
	p.skipSpace()
	if !p.consumeByte('(') {
		return node{}, p.unexpected(fmt.Sprintf("expected ( after %s", name))
	}
	args, err := p.parseValues(name)
	if err != nil {
		return node{}, err
	}
	n, bad := build(name, args)
	if bad != nil {
		pos := start
		if bad.arg >= 0 {
			pos = args[bad.arg].pos
		}
		return node{}, p.errAt(pos, bad.msg)
	}
	return n, nil
}

// value is one quoted value and where its opening quote is.
type value struct {
	text string
	pos  int
}

// parseValues reads the comma-separated values of name( up to the closing
// parenthesis.
func (p *parser) parseValues(name string) ([]value, error) {
	var out []value
	p.skipSpace()
	if p.consumeByte(')') {
		return out, nil
	}
	for {
		p.skipSpace()
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipSpace()
		switch {
		case p.consumeByte(','):
			continue
		case p.consumeByte(')'):
			return out, nil
		case p.pos == len(p.src):
			return nil, p.errAt(p.pos, fmt.Sprintf("expected ) to close %s(, but the rule ends here", name))
		}
		return nil, p.unexpected(fmt.Sprintf("expected , or ) after a value of %s", name))
	}
}

func (p *parser) parseValue() (value, error) {
	if p.pos == len(p.src) {
		return value{}, p.errAt(p.pos, "expected a value in backticks, such as `example.com`, but the rule ends here")
	}
	q := p.src[p.pos]
	if q != '`' && q != '"' {
		return value{}, p.unexpected("expected a value in backticks or double quotes, such as `example.com`")
	}
	start := p.pos
	end := strings.IndexByte(p.src[start+1:], q)
	if end < 0 {
		return value{}, p.errAt(start, "this value's quote is never closed")
	}
	p.pos = start + 1 + end + 1
	return value{text: p.src[start+1 : start+1+end], pos: start}, nil
}

// ident reads a condition name: ASCII letters and digits.
func (p *parser) ident() string {
	start := p.pos
	for p.pos < len(p.src) && isIdentByte(p.src[p.pos]) {
		p.pos++
	}
	return p.src[start:p.pos]
}

func isIdentByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

func (p *parser) skipSpace() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) consume(tok string) bool {
	p.skipSpace()
	if strings.HasPrefix(p.src[p.pos:], tok) {
		p.pos += len(tok)
		return true
	}
	return false
}

func (p *parser) consumeByte(c byte) bool {
	if p.pos < len(p.src) && p.src[p.pos] == c {
		p.pos++
		return true
	}
	return false
}

// unexpected is an error at the current position that quotes what is there.
func (p *parser) unexpected(want string) error {
	if p.pos == len(p.src) {
		return p.errAt(p.pos, "the rule ends too early; "+want)
	}
	return p.errAt(p.pos, fmt.Sprintf("unexpected %s; %s", excerpt(p.src[p.pos:]), want))
}

func (p *parser) errAt(pos int, msg string) error {
	return &Error{Pos: p.charPos(pos), Msg: msg}
}

// charPos is the 1-based character position of byte offset pos.
func (p *parser) charPos(pos int) int {
	return utf8.RuneCountInString(p.src[:pos]) + 1
}

// excerpt quotes the start of s, short enough for an error message.
func excerpt(s string) string {
	const limit = 16
	end, n := 0, 0
	for end < len(s) && n < limit {
		_, size := utf8.DecodeRuneInString(s[end:])
		end += size
		n++
	}
	if end == len(s) {
		return fmt.Sprintf("%q", s)
	}
	return fmt.Sprintf("%q...", s[:end])
}
