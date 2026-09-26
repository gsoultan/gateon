// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIPFilterRefusesAPreflightFromABlockedAddress closes a bypass of the
// management plane's network boundary.
//
// IsCorsPreflight is three values the client writes: the OPTIONS method, an
// Origin header and an Access-Control-Request-Method header. IPFilter skipped
// itself for anything matching that shape, which made a network allowlist
// something a caller could opt out of by naming a preflight.
//
// On the HTTP entrypoint the skip was unreachable at the time, because a CORS
// middleware there answered preflights before anything else ran (removed
// since, ADR-0015). Neither the management listener nor the smart-TCP listener
// had it. Measured against the real chain:
//
//	plain GET, blocked IP      status=403  reached_backend=false
//	OPTIONS + CORS headers     status=418  reached_backend=true
//
// An allowlist states who may reach the gateway at all, so it answers before
// it considers what the caller says it wants.
func TestIPFilterRefusesAPreflightFromABlockedAddress(t *testing.T) {
	var reached bool
	h := IPFilter([]string{"127.0.0.1", "::1"}, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))

	r := httptest.NewRequest(http.MethodOptions, "http://mgmt.internal/v1/users", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Access-Control-Request-Method", "GET")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if reached {
		t.Error("a preflight from an address outside the allowlist reached the " +
			"backend; the network boundary is opt-out by writing three headers")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestIPFilterStillAllowsAPreflightFromAnAllowedAddress is the other half: the
// fix must not turn legitimate CORS from a permitted network into a refusal.
func TestIPFilterStillAllowsAPreflightFromAnAllowedAddress(t *testing.T) {
	var reached bool
	h := IPFilter([]string{"127.0.0.1", "::1"}, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))

	r := httptest.NewRequest(http.MethodOptions, "http://mgmt.internal/v1/users", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("Origin", "https://app.example")
	r.Header.Set("Access-Control-Request-Method", "GET")

	h.ServeHTTP(httptest.NewRecorder(), r)

	if !reached {
		t.Error("a preflight from an allowed address was refused; CORS against " +
			"the management API from a permitted network would stop working")
	}
}

// TestIPFilterDeniesWhenEveryAllowEntryIsMalformed covers a second way this
// boundary was opt-out, this one by operator typo rather than by request.
//
// An empty allow structure means "no allow list configured" and admits
// everyone. Entries were inserted with the parse error discarded, so an allow
// list whose entries all failed to parse became no allow list at all:
// `allow_list: "10.0.0/8"` -- one missing octet -- answered 200 to
// 203.0.113.9 with nothing logged.
//
// Configured-but-unusable now denies. An operator who wrote an allow list
// meant to restrict something, and the dropped entries are logged so the
// cause is visible rather than inferred from traffic.
func TestIPFilterDeniesWhenEveryAllowEntryIsMalformed(t *testing.T) {
	var reached bool
	h := IPFilter([]string{"10.0.0/8"}, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))

	r := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	h.ServeHTTP(httptest.NewRecorder(), r)

	if reached {
		t.Error("an allow list whose every entry failed to parse admitted a " +
			"client it was written to exclude; one typo opens the route")
	}
}

// TestIPFilterWithNoAllowListStillAllows keeps the distinction honest: no
// allow list at all must go on meaning "no restriction", or every route
// without one starts refusing traffic.
func TestIPFilterWithNoAllowListStillAllows(t *testing.T) {
	var reached bool
	h := IPFilter(nil, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))

	r := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	h.ServeHTTP(httptest.NewRecorder(), r)

	if !reached {
		t.Error("a filter with no allow list refused a client; routes without " +
			"an allow list must stay unrestricted")
	}
}
