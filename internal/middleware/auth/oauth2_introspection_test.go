// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// introspectionFixture stands up a fake RFC 7662 endpoint and a validator
// pointed at it, and reports whether the protected handler was reached.
func introspectionFixture(t *testing.T, h http.HandlerFunc) (*httptest.ResponseRecorder, *bool) {
	t.Helper()
	idp := httptest.NewServer(h)
	t.Cleanup(idp.Close)

	v, err := NewOAuth2IntrospectionValidator(OAuth2IntrospectionConfig{
		IntrospectionURL: idp.URL, ClientID: "cid", ClientSecret: "csecret",
	})
	if err != nil {
		t.Fatalf("NewOAuth2IntrospectionValidator: %v", err)
	}

	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer opaque-token")
	rec := httptest.NewRecorder()
	v.Handler(next).ServeHTTP(rec, req)
	return rec, &reached
}

// TestIntrospectionFailureDoesNotLeakTheProvidersResponse is the regression
// test for an information disclosure.
//
// introspect wrapped the provider's response body into its error, Handler
// wrapped that again, and HandleFailure writes err.Error() into the response.
// So an unhealthy provider's own output -- connection strings, trace IDs,
// whatever it prints -- was returned to a caller who had not authenticated,
// twice, in both JSON fields.
func TestIntrospectionFailureDoesNotLeakTheProvidersResponse(t *testing.T) {
	secret := `{"error":"db down at postgres://idp-internal.corp:5432, trace=abc123"}`
	rec, reached := introspectionFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, secret)
	})

	if *reached {
		t.Error("request reached the protected handler despite introspection failing")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	body := rec.Body.String()
	for _, leak := range []string{"postgres://", "idp-internal.corp", "5432", "trace=abc123", "500"} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaks %q to an unauthenticated caller: %s", leak, body)
		}
	}
}

// TestIntrospectionFailsClosed covers every way the provider can fail to give a
// usable answer. None of them may be read as "the token is fine".
func TestIntrospectionFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"provider returns 500", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{"provider returns 403", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}},
		{"provider returns unparseable json", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "<html>not json</html>")
		}},
		{"provider says the token is inactive", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"active":false}`)
		}},
		{"provider omits active entirely", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"sub":"someone"}`)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, reached := introspectionFixture(t, tt.handler)
			if *reached {
				t.Error("the protected handler was reached")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

// TestIntrospectionAllowsAnActiveToken is the other half: the guard has to let
// a valid token through, or the tests above would pass with a handler that
// denied everything.
func TestIntrospectionAllowsAnActiveToken(t *testing.T) {
	rec, reached := introspectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("provider could not parse the form: %v", err)
		}
		if got := r.PostFormValue("token"); got != "opaque-token" {
			t.Errorf("provider received token %q, want the caller's", got)
		}
		if got := r.PostFormValue("client_id"); got != "cid" {
			t.Errorf("provider received client_id %q, want cid", got)
		}
		fmt.Fprint(w, `{"active":true,"sub":"user-7","scope":"read write","tenant":"acme"}`)
	})

	if !*reached {
		t.Error("an active token was rejected")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestIntrospectionResponseIsBounded pins the read limit. The body comes from
// another service, and an unbounded read is one bad dependency away from
// exhausting memory on the request path.
func TestIntrospectionResponseIsBounded(t *testing.T) {
	rec, reached := introspectionFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Far past the cap, and invalid JSON once truncated, so a request that
		// survives this is one that read the whole thing.
		fmt.Fprint(w, `{"active":true,"padding":"`)
		chunk := strings.Repeat("A", 8<<10)
		for range 32 { // 256 KiB, against a 64 KiB cap
			fmt.Fprint(w, chunk)
		}
		fmt.Fprint(w, `"}`)
	})

	if *reached {
		t.Error("a response larger than the cap was accepted as valid")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestNewOAuth2IntrospectionValidatorRequiresItsCredentials keeps a
// half-configured validator from being built and then failing every request at
// runtime, which reads as "the provider is down" rather than "this is
// misconfigured".
func TestNewOAuth2IntrospectionValidatorRequiresItsCredentials(t *testing.T) {
	full := OAuth2IntrospectionConfig{IntrospectionURL: "https://idp/introspect", ClientID: "cid", ClientSecret: "sec"}
	if _, err := NewOAuth2IntrospectionValidator(full); err != nil {
		t.Fatalf("a complete config was rejected: %v", err)
	}

	for _, tt := range []struct {
		name string
		cfg  OAuth2IntrospectionConfig
	}{
		{"no url", OAuth2IntrospectionConfig{ClientID: "cid", ClientSecret: "sec"}},
		{"no client id", OAuth2IntrospectionConfig{IntrospectionURL: "https://idp/x", ClientSecret: "sec"}},
		{"no client secret", OAuth2IntrospectionConfig{IntrospectionURL: "https://idp/x", ClientID: "cid"}},
		{"whitespace is not a value", OAuth2IntrospectionConfig{IntrospectionURL: "  ", ClientID: " ", ClientSecret: "\t"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewOAuth2IntrospectionValidator(tt.cfg); err == nil {
				t.Error("an incomplete config was accepted")
			}
		})
	}
}

// TestIntrospectionExtrasReachTheClaims covers UnmarshalJSON's reason for
// existing: provider-specific claims a route may be authorising on.
func TestIntrospectionExtrasReachTheClaims(t *testing.T) {
	var resp oauth2IntrospectionResponse
	if err := resp.UnmarshalJSON([]byte(`{"active":true,"sub":"u1","scope":"read","tenant":"acme","groups":["a","b"]}`)); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if !resp.Active || resp.Sub != "u1" || resp.Scope != "read" {
		t.Errorf("standard fields = %+v, want active/u1/read", resp)
	}
	if resp.Extras["tenant"] != "acme" {
		t.Errorf("Extras[tenant] = %v, want acme", resp.Extras["tenant"])
	}
	if _, ok := resp.Extras["groups"]; !ok {
		t.Error("Extras dropped a non-scalar claim")
	}
}
