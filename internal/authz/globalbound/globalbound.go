// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package globalbound decides which global settings a caller who is not an
// administrator may change.
//
// The operator role holds write on the global configuration, and the global
// configuration holds the security boundary itself: whether authentication is
// on, the session key, the RBAC rules, the audit settings, where the
// management plane listens and whom it admits. An operator could therefore
// switch authentication off, expose the management API on every entrypoint,
// and reset the administrator's password anonymously -- or switch audit off
// with no record that it had been. ADR 0040.
//
// The rule: every field reachable from GlobalConfig is classified (classes.go)
// as Boundary -- administrator-only -- or Operational. A save by a caller who
// is not an administrator is refused, naming the fields, when it changes any
// Boundary field from what is stored. The dashboard sends the whole object
// back, so a Boundary field sent back unchanged -- including a secret that
// came back as the stored-secret placeholder (restored before this runs) or
// as its reference -- is not a change.
//
// The guard runs inside the API's global-config save, which REST, Connect and
// gRPC share, and the internal writers in internal/api use the same check.
// It fails closed: a caller whose claims cannot be read is not an
// administrator, and no claims at all while authentication is in force is
// not one either.
package globalbound

import (
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ErrRequiresAdmin refuses a save by a non-administrator that changes a
// boundary setting. Callers map it to 403 / PermissionDenied.
var ErrRequiresAdmin = errors.New("only an administrator may change")

// maxNamed bounds how many fields a refusal names; the rest are counted.
const maxNamed = 8

// Caller is who is saving, as the API read it from the request.
type Caller struct {
	// Claims are the caller's claims; nil when there were none, or when the
	// value present could not be read as *auth.Claims.
	Claims *auth.Claims
	// ClaimsPresent reports whether the request carried a claims value at all.
	ClaimsPresent bool
	// AuthEnforced reports whether authentication is in force: the stored
	// configuration has it on and an auth service exists.
	AuthEnforced bool
}

// restricted reports whether the caller is held to the administrator-only
// rule. A claims value that could not be read establishes nothing, and so is
// not an administrator. No claims at all means nobody authenticated the
// request: that is only "the management plane is open by configuration" when
// authentication is in fact off.
func (c Caller) restricted() bool {
	if c.ClaimsPresent {
		return c.Claims == nil || c.Claims.Role != auth.RoleAdmin
	}
	return c.AuthEnforced
}

// Change is one proposed save of the global configuration.
type Change struct {
	// Stored is the configuration in force.
	Stored *gateonv1.GlobalConfig
	// View is Stored as a writer reads it -- each secret configured as a
	// reference shown as that reference -- so a reference sent back unchanged
	// is not a change. Nil means Stored.
	View *gateonv1.GlobalConfig
	// Proposed is the configuration the caller wants stored, with every
	// stored-secret placeholder already restored.
	Proposed *gateonv1.GlobalConfig
}

// RefusalError names the boundary fields a refused save would have changed.
type RefusalError struct {
	Fields []string
}

func (e *RefusalError) Error() string {
	named := e.Fields
	more := ""
	if len(named) > maxNamed {
		more = fmt.Sprintf(" and %d more", len(named)-maxNamed)
		named = named[:maxNamed]
	}
	return fmt.Sprintf("%s %s%s: these settings decide who can reach or sign in to the management plane, "+
		"whom the gateway trusts, or what record is kept of either", ErrRequiresAdmin, strings.Join(named, ", "), more)
}

// Unwrap makes errors.Is(err, ErrRequiresAdmin) hold.
func (e *RefusalError) Unwrap() error { return ErrRequiresAdmin }

// Authorize refuses a save by a caller who is not an administrator that
// changes any boundary field. An administrator, a caller on a deployment
// whose authentication is off, and a save that leaves every boundary field as
// stored all return nil.
func Authorize(c Caller, ch Change) error {
	if !c.restricted() {
		return nil
	}
	if fields := ChangedBoundary(ch); len(fields) > 0 {
		return &RefusalError{Fields: fields}
	}
	return nil
}

// ChangedBoundary returns the path of every boundary field ch changes, in
// proto field order.
func ChangedBoundary(ch Change) []string {
	t, ok := newTriple(ch)
	if !ok {
		return nil
	}
	d := differ{pick: boundaryPick}
	d.walk(t, "", false)
	return d.paths()
}

// FieldChange is one changed field, with its old and new values.
type FieldChange struct {
	Path     string
	From, To protoreflect.Value
	Field    protoreflect.FieldDescriptor
}

// RecordChanges returns every change ch makes to the settings that decide
// what record is kept of management activity: the audit section and the
// audit log's retention. Changing one is audited before it takes effect.
func RecordChanges(ch Change) []FieldChange {
	t, ok := newTriple(ch)
	if !ok {
		return nil
	}
	d := differ{pick: recordPick}
	d.walk(t, "", false)
	return d.changes
}

// DescribeRecordChanges renders changes for an audit entry. Booleans, numbers
// and enums show their old and new values; anything else -- a key, a
// database URL -- is only named, so the entry never carries a secret.
func DescribeRecordChanges(changes []FieldChange) string {
	parts := make([]string, 0, len(changes))
	for _, c := range changes {
		parts = append(parts, describe(c))
	}
	return strings.Join(parts, "; ")
}

func describe(c FieldChange) string {
	if c.Field.IsList() || c.Field.IsMap() {
		return c.Path + " changed"
	}
	switch c.Field.Kind() {
	case protoreflect.BoolKind, protoreflect.Int32Kind, protoreflect.Int64Kind,
		protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.EnumKind:
		return fmt.Sprintf("%s %v -> %v", c.Path, c.From.Interface(), c.To.Interface())
	default:
		return c.Path + " changed"
	}
}
