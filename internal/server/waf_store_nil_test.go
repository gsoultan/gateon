// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/gsoultan/gateon/internal/security/waf"
)

// TestResolveWafStoresSurvivesATypedNilStore pins the startup path against the
// shape that made `!= nil` read "a store is present" at exactly the moment it
// was not.
//
// waf.InitStore leaves the package store nil when the management database
// cannot be opened -- an unreachable Postgres DSN, or a SQLite path in a
// directory the process cannot write. main.go logs that and carries on, then
// hands waf.GetStore() to WithWafRules unconditionally. What arrives is a typed
// nil: an interface holding (*waf.Store)(nil), which is not equal to nil, so
// the guard passed and the first method call dereferenced the nil receiver on
// its own mutex. A misconfigured database took the gateway down at boot rather
// than starting it without WAF rule persistence.
func TestResolveWafStoresSurvivesATypedNilStore(t *testing.T) {
	t.Parallel()

	// What GetStore() returns when InitStore failed, boxed the way
	// WithWafRules boxes it. The interface is non-nil -- it carries the type
	// *waf.Store with a nil value -- which is the whole reason the `!= nil`
	// guard this replaced let a nil receiver through. staticcheck rejects
	// asserting that in code (SA4023, "this comparison is never true"), which
	// is a fair point: it is a property of the language, not of this package.
	var missing *waf.Store
	var held any = missing

	rules, exceptions := resolveWafStores(context.Background(), held, nil)

	if rules != nil {
		t.Errorf("rules = %v, want nil: a store that was never opened must not be treated as usable", rules)
	}
	if exceptions != nil {
		t.Errorf("exceptions = %v, want nil", exceptions)
	}
}

// TestResolveWafStoresIgnoresAnUnrelatedValue covers the other half of the
// comma-ok: WafRules is typed `any`, so a caller can put anything in it, and a
// wrong type must skip the wiring rather than panic in a type assertion.
func TestResolveWafStoresIgnoresAnUnrelatedValue(t *testing.T) {
	t.Parallel()

	rules, exceptions := resolveWafStores(context.Background(), "not a store", nil)

	if rules != nil || exceptions != nil {
		t.Errorf("rules = %v, exceptions = %v, want both nil", rules, exceptions)
	}
}
