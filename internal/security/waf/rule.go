// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package waf

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/gsoultan/gwaf/rules"
)

// Rule formats.
const (
	// FormatGateon is the typed Definition, the only format that is enforced.
	FormatGateon = "gateon"

	// FormatSecLang is the ModSecurity text a rule was authored in before the
	// engine migration. A rule in this format is *not* loaded: gateon no longer
	// has a SecLang engine, and running a rule it cannot compile is impossible
	// while silently treating it as satisfied would be worse. The row is kept,
	// flagged in the dashboard, and the operator converts it.
	FormatSecLang = "seclang"
)

// Rule represents a WAF security rule stored in the database.
type Rule struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// Directive is the original SecLang text, retained for rules authored
	// before the engine migration. It is never executed. It is kept because it
	// is the only record of what an unconverted rule was meant to do, and
	// discarding it would make a failed conversion unrecoverable.
	Directive string `json:"directive,omitempty"`

	// Definition is the typed rule, as JSON. See Definition.
	Definition string `json:"definition,omitempty"`

	// Format is FormatGateon or FormatSecLang.
	Format string `json:"format"`

	// ConversionNote records why a rule could not be converted automatically.
	// It is shown to the operator next to the rule.
	ConversionNote string `json:"conversion_note,omitempty"`

	Enabled       bool      `json:"enabled"`
	ParanoiaLevel int       `json:"paranoia_level"`
	Category      string    `json:"category"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Scan targets. The three migrated columns are nullable on rows written before
// migration 60, so they are read through sql.NullString rather than assuming a
// value the database does not guarantee.
func (r *Rule) scanTargets() []any {
	return []any{
		&r.ID, &r.Name,
		nullable(&r.Directive), nullable(&r.Definition),
		nullable(&r.Format), nullable(&r.ConversionNote),
		&r.Enabled, &r.ParanoiaLevel, &r.Category,
		&r.CreatedAt, &r.UpdatedAt,
	}
}

// nullable returns a scan destination that leaves dst empty for a SQL NULL.
func nullable(dst *string) any { return &nullString{dst: dst} }

type nullString struct{ dst *string }

func (n *nullString) Scan(src any) error {
	var v sql.NullString
	if err := v.Scan(src); err != nil {
		return err
	}
	*n.dst = v.String
	return nil
}

// Compiled returns the rule as a gwaf rule.
//
// A rule still in SecLang format is an error rather than a skip: the caller
// decides whether to drop it or refuse to start, and neither should happen by
// accident.
func (r Rule) Compiled() (rules.Rule, error) {
	if r.Format != FormatGateon {
		return rules.Rule{}, fmt.Errorf(
			"rule %s (%s) is still in %s format and cannot be enforced; convert it in the dashboard",
			r.ID, r.Name, r.formatName())
	}
	d, err := ParseDefinition(r.Definition)
	if err != nil {
		return rules.Rule{}, fmt.Errorf("rule %s (%s): %w", r.ID, r.Name, err)
	}
	id, err := r.numericID()
	if err != nil {
		return rules.Rule{}, err
	}
	rule, err := d.Compile(id)
	if err != nil {
		return rules.Rule{}, fmt.Errorf("rule %s (%s): %w", r.ID, r.Name, err)
	}
	return rule, nil
}

func (r Rule) formatName() string {
	if r.Format == "" {
		return FormatSecLang
	}
	return r.Format
}

// numericID converts the stored identifier to a gwaf rule ID.
//
// gwaf reserves everything below types.UserMin for itself, and gateon's own
// rules were numbered above it already, so historical IDs carry over unchanged.
// A rule whose ID is not a number — the UUID that AddRule generates for a rule
// created through the dashboard — is hashed into the embedder range instead,
// deterministically, so the same rule keeps the same ID across restarts and
// across replicas.
func (r Rule) numericID() (uint32, error) {
	if n, err := parseUint32(r.ID); err == nil {
		if n >= userRuleIDMin {
			return n, nil
		}
		return 0, fmt.Errorf("rule %s: numeric IDs below %d are reserved by the engine",
			r.ID, userRuleIDMin)
	}
	return hashedRuleID(r.ID), nil
}
