// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import "testing"

// POST /v1/setup/test-db is the first-run wizard's "test connection" button —
// ui/src/routes/SetupPage.tsx calls it through testDbConnection() before an
// administrator exists.
//
// It was unreachable in every state the gateway can be in. isPublicAuthPath
// matches "/v1/setup" exactly, so on a first run the base handler answered 503
// ("setup incomplete") for the one window the endpoint is *for*; and once setup
// completes the handler itself answers 403 ("only allowed during initial
// setup"). Two correct-looking guards that between them left no reachable state.
//
// Nothing caught it because the endpoint had no test and no e2e spec, and a
// button that always errors looks like a database problem rather than a routing
// one.
func TestSetupTestDBIsReachableBeforeAnAdministratorExists(t *testing.T) {
	if !isPublicAuthPath("/v1/setup/test-db") {
		t.Fatal("POST /v1/setup/test-db is not a public auth path, so the base handler " +
			"answers 503 during first run — which is the only window the handler itself permits it")
	}
}

// The neighbours must stay public, and the guard must stay exact-match: a
// prefix match on "/v1/setup" would make every future /v1/setup/* endpoint
// unauthenticated by accident.
func TestPublicAuthPathsAreExactAndMinimal(t *testing.T) {
	for _, p := range []string{
		"/v1/setup",
		"/v1/setup/required",
		"/v1/setup/test-db",
		"/healthz",
		"/readyz",
	} {
		if !isPublicAuthPath(p) {
			t.Errorf("%s should be reachable before setup completes", p)
		}
	}
	// Anything that mutates configuration or reads secrets must not be.
	for _, p := range []string{
		"/v1/setup/../global",
		"/v1/global",
		"/v1/routes",
		"/v1/users",
		"/v1/config/export",
		"/v1/certs",
		"/v1/setupX",
	} {
		if isPublicAuthPath(p) {
			t.Errorf("%s must not skip authentication", p)
		}
	}
}
