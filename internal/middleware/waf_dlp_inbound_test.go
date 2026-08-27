// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
)

// inboundDLPHandler builds a WAF with inbound data-leak detection active and an
// origin that reports whether the request reached it.
func inboundDLPHandler(t *testing.T) (http.Handler, *bool) {
	t.Helper()

	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Migrate(d, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := waf.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	mw, err := WAF(WAFConfig{
		EnableDLP:        true,
		ParanoiaLevel:    2,
		WafRules:         store,
		RequestBodyLimit: 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	reached := new(bool)
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	})), reached
}

// TestInboundSecretReachesTheOriginAndIsRecorded is the behaviour the inbound
// direction is designed around. The secret is seen and reported, and the
// request still lands: a support ticket that vanishes because it quoted an AWS
// key is a ticket the user re-files somewhere gateon cannot see.
func TestInboundSecretReachesTheOriginAndIsRecorded(t *testing.T) {
	handler, reached := inboundDLPHandler(t)

	body := `{"message":"deploy is broken, key is AKIAIOSFODNN7EXAMPLE"}`
	req := httptest.NewRequest(http.MethodPost, "/tickets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("inbound secret detection blocked the request: status %d", rec.Code)
	}
	if !*reached {
		t.Error("the request never reached the origin")
	}
}

// TestCheckoutTrafficIsUnaffected is the false positive that would matter most.
// A card number in a request is a customer paying for something, and the
// inbound rules carry no card detector for exactly this reason.
func TestCheckoutTrafficIsUnaffected(t *testing.T) {
	handler, reached := inboundDLPHandler(t)

	body := `{"card":"4111111111111111","exp":"12/29","cvv":"123","ssn":"123-45-6789"}`
	req := httptest.NewRequest(http.MethodPost, "/checkout", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("checkout traffic was blocked: status %d", rec.Code)
	}
	if !*reached {
		t.Error("checkout request never reached the origin")
	}
}

// TestInboundDLPDoesNotWeakenTheRestOfTheWAF checks that adding a logging rule
// class did not make anything else stop refusing. An injection in the same
// request body must still be a 403.
func TestInboundDLPDoesNotWeakenTheRestOfTheWAF(t *testing.T) {
	handler, reached := inboundDLPHandler(t)

	req := httptest.NewRequest(http.MethodGet,
		"/search?q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("SQL injection was not blocked: status %d", rec.Code)
	}
	if *reached {
		t.Error("a blocked request still reached the origin")
	}
}
