// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import "testing"

// resetTLSCaches gives a test its own view of the three package-level TLS
// caches.
//
// certCache, certPoolCache and tlsConfigCache are sync.Maps keyed on
// configuration ids -- "cert1", "pool:ca1", and the route id for the whole
// per-route *tls.Config. Every TLS test in this package uses route id "r1",
// so without this the first test to build a config decides what every later
// test sees, and the assertions in the later ones stop describing their own
// setup.
//
// That is not hypothetical: under -shuffle=on,
// TestSetupSNI_BindsClientAuthoritiesFromTLSOption got NoClientCert instead of
// RequireAndVerifyClientCert, because a test that ran earlier had already
// cached a config for "r1" built without the mTLS option. CI runs in
// declaration order and never saw it. A test that passes only in one order is
// not testing what it claims in any order.
//
// Cleared on the way in as well as out, so a test is protected from whatever
// ran before it even if that test predates this helper.
func resetTLSCaches(t *testing.T) {
	t.Helper()
	InvalidateTLSCache()
	t.Cleanup(InvalidateTLSCache)
}
