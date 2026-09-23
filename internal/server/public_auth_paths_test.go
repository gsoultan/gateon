// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
)

const apiProcedurePrefix = "/gateon.v1.ApiService/"

// TestPublicAuthPathsNameRealProcedures keeps a dead entry out of the
// authentication-exemption list.
//
// Two used to sit there -- ApiService/Enroll2FA and ApiService/Verify2FA --
// naming procedures ApiService does not declare. They matched nothing, which
// is why nobody noticed, and that is the whole problem: the day either RPC is
// added it arrives *already exempt from authentication*, with no diff to
// review, because the exemption was written years before the endpoint.
//
// This is the same accident the exact-match rule in publicAuthPaths exists to
// prevent. That rule stops a prefix catching future endpoints; this stops a
// name doing it.
func TestPublicAuthPathsNameRealProcedures(t *testing.T) {
	iface := reflect.TypeOf((*gateonv1connect.ApiServiceHandler)(nil)).Elem()

	declared := make(map[string]bool, iface.NumMethod())
	for i := range iface.NumMethod() {
		declared[apiProcedurePrefix+iface.Method(i).Name] = true
	}

	for path := range publicAuthPaths {
		if !strings.HasPrefix(path, apiProcedurePrefix) {
			continue
		}
		if !declared[path] {
			t.Errorf("%s is exempt from authentication but ApiService does not declare it; "+
				"either the procedure was removed and this entry should go, or it was "+
				"never added and this entry is pre-authorising one", path)
		}
	}
}

// TestSetup2FAIsNotPublic pins the line the list is drawn on. /v1/auth/2fa/enroll
// and /v1/auth/2fa/verify are the login flow's pre-session steps and must be
// reachable without a token. /v1/auth/2fa/setup returns the TOTP secret, the QR
// code and the recovery codes, and must not.
func TestSetup2FAIsNotPublic(t *testing.T) {
	if isPublicAuthPath("/v1/auth/2fa/setup") {
		t.Error("/v1/auth/2fa/setup skips authentication; it hands out the TOTP " +
			"secret and recovery codes, so it must authenticate and then refuse " +
			"any id but the caller's own")
	}
	for _, p := range []string{"/v1/auth/2fa/enroll", "/v1/auth/2fa/verify"} {
		if !isPublicAuthPath(p) {
			t.Errorf("%s requires authentication, but it is a step of the login "+
				"flow that runs before a session exists", p)
		}
	}
}

// TestPublicAuthPathsAreExactNotPrefixes: the comment on publicAuthPaths says
// membership is exact so a future /v1/setup/* endpoint cannot become
// unauthenticated by accident. The handler behind /v1/setup/test-db opens a
// database connection to a caller-supplied DSN, so this is not a style point.
func TestPublicAuthPathsAreExactNotPrefixes(t *testing.T) {
	for _, p := range []string{
		"/v1/setup/anything-added-later",
		"/v1/setup/test-db/extra",
		"/v1/auth/2fa/setup",
		"/gateon.v1.ApiService/SetupSomethingElse",
	} {
		if isPublicAuthPath(p) {
			t.Errorf("%s is treated as public; membership must be exact, or every "+
				"endpoint added under one of these prefixes ships unauthenticated", p)
		}
	}
}
