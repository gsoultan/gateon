// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// An auth middleware stored before ADR 0043 -- an OIDC one with no audience, a
// basic-auth list with a user who has no password -- no longer builds, and the
// route serves the refusal of an unbuildable security middleware (503) instead
// of the hole: the request the old config let through, a token issued to
// another application or a login with no password, no longer reaches the origin.
func TestARouteWhoseStoredAuthIsNowUnsafeRefusesInsteadOfServing(t *testing.T) {
	idp := testutil.NewFakeOIDCProvider(t, "some-other-app")
	tok, err := idp.Mint("alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cfg  map[string]string
		send func(r *http.Request)
	}{
		{"oidc with no audience", map[string]string{"type": "oidc", "issuer": idp.Issuer()},
			func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }},
		{"basic user with no password", map[string]string{"type": "basic", "users": "alice:pw1,user2:"},
			func(r *http.Request) { r.SetBasicAuth("user2", "") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
			store := &stubMiddlewareStore{mws: map[string]*gateonv1.Middleware{
				"authn": {Id: "authn", Name: "authn", Type: "auth", Config: tc.cfg},
			}}
			rt := &gateonv1.Route{Id: "r-" + tc.name, Name: "r-" + tc.name, Middlewares: []string{"authn"}}
			h := ApplyRouteMiddlewares(origin, rt, nil, store, nil, nil, nil)

			req := httptest.NewRequest(http.MethodGet, "http://x/private", nil)
			tc.send(req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status %d, want 503 (418 means the request reached the origin)", rec.Code)
			}
		})
	}
}
