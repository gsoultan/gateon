// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package apischema turns the OpenAPI document an operator pastes into a route
// WAF into the schema the engine checks requests against.
//
// It is its own package for two reasons. The YAML parser arrives with gwaf's
// OpenAPI frontend, and nothing that does not read a document should import
// it. And both WAF packages are at the folder limit (ADR 0010), so a new
// concern gets a home rather than an eleventh file.
package apischema

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gsoultan/gwaf/schema"
	"github.com/gsoultan/gwaf/schema/openapi"
)

// MaxDocumentBytes bounds the document. It is held in the middleware's config
// row and parsed on every engine build, so it is a config value and has a
// config value's size: 1 MiB holds an API of several hundred operations.
const MaxDocumentBytes = 1 << 20

// Mode says what a request outside the document costs its sender.
type Mode uint8

const (
	// Record lets the request through to the rules and counts the violation.
	// The default: a published document is usually narrower than the traffic
	// the API serves, and the way to find out by how much is to run it.
	Record Mode = iota
	// Enforce refuses the request before any rule runs.
	Enforce
)

// The values of the openapi_mode setting.
const (
	ModeRecord  = "record"
	ModeEnforce = "enforce"
)

// String is the setting's value.
func (m Mode) String() string {
	if m == Enforce {
		return ModeEnforce
	}
	return ModeRecord
}

// ErrUnknownMode is a mode other than the two.
var ErrUnknownMode = errors.New(`the OpenAPI mode must be "record" or "enforce"`)

// ParseMode reads the openapi_mode setting. Empty is Record.
//
// A value it does not know is an error rather than a default in either
// direction: read as Record it leaves an operator who typed "enforced"
// believing requests are refused, and read as Enforce it refuses traffic on a
// typo.
func ParseMode(v string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", ModeRecord:
		return Record, nil
	case ModeEnforce:
		return Enforce, nil
	default:
		return Record, ErrUnknownMode
	}
}

// Report says what a document contributes, so that one which compiles and
// constrains nothing is not mistaken for protection.
type Report struct {
	// Operations is how many method-and-path pairs the document describes.
	Operations int
	// Fields is how many parameters carry a constraint a request can break.
	Fields int
	// Inert is how many of those are typed tightly enough (an integer, a
	// UUID, an enum) that a valid value cannot carry an attack.
	Inert int
	// Skipped names what the document declares and the engine cannot use.
	Skipped []string
}

// Errors Compile returns. Each is worded for the operator who pasted the
// document: it is shown to them when the save is refused.
var (
	ErrTooLarge   = fmt.Errorf("the OpenAPI document is larger than %d KiB", MaxDocumentBytes>>10)
	ErrNoPaths    = errors.New("the OpenAPI document describes no operations, so it would check nothing")
	errUnusable   = errors.New("the OpenAPI document could not be read")
	errNotOpenAPI = errors.New("this is not an OpenAPI 3 document (Swagger 2.0 is not supported)")
)

// Compile reads an OpenAPI 3 document, in YAML or JSON.
//
// A document that describes no operation is refused rather than loaded: a
// route showing "OpenAPI: on" with nothing behind it is the failure this
// whole feature exists to avoid.
func Compile(doc string) (*schema.Schema, Report, error) {
	if len(doc) > MaxDocumentBytes {
		return nil, Report{}, ErrTooLarge
	}
	ops, rep, err := openapi.Compile([]byte(doc), openapi.Options{})
	switch {
	case errors.Is(err, openapi.ErrNotOpenAPI), errors.Is(err, openapi.ErrUnsupportedVersion):
		return nil, Report{}, errNotOpenAPI
	case err != nil:
		return nil, Report{}, fmt.Errorf("%w: %w", errUnusable, err)
	case len(ops) == 0:
		return nil, Report{}, ErrNoPaths
	}
	s, err := schema.New(ops...)
	if err != nil {
		return nil, Report{}, fmt.Errorf("%w: %w", errUnusable, err)
	}
	return s, Report{
		Operations: rep.Operations,
		Fields:     rep.Fields,
		Inert:      rep.Inert,
		Skipped:    rep.Skipped,
	}, nil
}
