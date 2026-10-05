// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCredentialChecked: a refusal can be a refused credential only when the
// backend wrote it or the gateway's authentication did (ADR 0059).
func TestCredentialChecked(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refused Refusal
		reached bool
		want    bool
	}{
		{"a backend's answer", RefusalNone, true, true},
		{"a gateway layer before the service", RefusalNone, false, false},
		{"the gateway's authentication", RefusalAuthentication, false, true},
		{"a token the gateway verified", RefusalToken, false, false},
		{"a shun", RefusalMitigation, false, false},
	} {
		rs := &RequestState{Refused: tc.refused}
		if tc.reached {
			rs.TServiceStart = 1
		}
		if got := rs.CredentialChecked(); got != tc.want {
			t.Errorf("%s: CredentialChecked = %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := RefusalAuthentication.String(); got != "authentication" {
		t.Errorf("RefusalAuthentication is traced as %q", got)
	}
}

// TestServiceBoundaryStampsWhatReachedTheService: what tells a backend's
// answer from the gateway's own.
func TestServiceBoundaryStampsWhatReachedTheService(t *testing.T) {
	rs := &RequestState{}
	var startedBeforeService bool
	h := ServiceBoundary(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		startedBeforeService = rs.TServiceStart > 0 && rs.TServiceEnd == 0
		w.WriteHeader(http.StatusUnauthorized)
	}))
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	h.ServeHTTP(httptest.NewRecorder(), req.WithContext(WithState(req.Context(), rs)))
	if !startedBeforeService || rs.TServiceEnd < rs.TServiceStart {
		t.Fatalf("the boundary stamped start=%d end=%d around the service", rs.TServiceStart, rs.TServiceEnd)
	}
	if !rs.CredentialChecked() {
		t.Error("a backend's 401 is not one a credential check can have written")
	}
	// Without request state there is nothing to stamp, and nothing breaks.
	ServiceBoundary(http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

// TestMarkRefusedContext marks the state a handler holding only the context
// can reach, as MarkRefused does through the request.
func TestMarkRefusedContext(t *testing.T) {
	rs := &RequestState{}
	MarkRefusedContext(WithState(t.Context(), rs), RefusalAuthentication)
	if rs.Refused != RefusalAuthentication {
		t.Fatalf("marked %q", rs.Refused)
	}
	MarkRefusedContext(t.Context(), RefusalToken) // no state: nothing to mark, and no panic
}
