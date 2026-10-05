// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// An introspected OAuth2 token the provider calls inactive is refused by the
// gateway's own verification, and the request is marked so (ADR 0031); one
// that presented no token is refused by authentication for that, and marked
// as such (ADR 0059).
func TestIntrospectionMarksOnlyAPresentedTokenItRefused(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	t.Cleanup(idp.Close)
	v, err := NewOAuth2IntrospectionValidator(OAuth2IntrospectionConfig{
		IntrospectionURL: idp.URL, ClientID: "cid", ClientSecret: "csecret",
	})
	if err != nil {
		t.Fatal(err)
	}
	h := v.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, tc := range []struct {
		name, authorization string
		want                request.Refusal
	}{
		{"an inactive token", "Bearer opaque-token", request.RefusalToken},
		{"no token", "", request.RefusalAuthentication},
	} {
		rs := &request.RequestState{}
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		if tc.authorization != "" {
			req.Header.Set("Authorization", tc.authorization)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req.WithContext(request.WithState(req.Context(), rs)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: answered %d, want 401", tc.name, rec.Code)
		}
		if rs.Refused != tc.want {
			t.Errorf("%s refused 401: the request is marked %q, want %q", tc.name, rs.Refused, tc.want)
		}
	}
}
