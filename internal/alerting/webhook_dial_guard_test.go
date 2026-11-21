// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gsoultan/gateon/internal/mgmtaddr"
)

// Alert webhooks went out through http.DefaultClient, the one HTTP client in
// the gateway that dials whatever a destination resolves to (review L2): a
// webhook naming, or redirecting to, this gateway's own management listener
// or a cloud metadata service was dialled like any other. They now go through
// the dial guard every backend connection already passes.
func TestAWebhookCannotReachTheManagementListener(t *testing.T) {
	var reached bool
	mgmt := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer mgmt.Close()
	ap := netip.MustParseAddrPort(mgmt.Listener.Addr().String())
	defer mgmtaddr.Register(mgmtaddr.Register(int(ap.Port())))

	err := sendWebhook(context.Background(), mgmt.URL+"/v1/anything", map[string]string{"text": "x"})
	if !errors.Is(err, mgmtaddr.ErrManagementListener) || reached {
		t.Fatalf("send = %v, reached %t; want it refused before connecting", err, reached)
	}
}

// A redirect is dialled through the same guard, so a receiver cannot bounce
// the alert, and the token in its URL, on to the management listener.
func TestAWebhookRedirectCannotReachTheManagementListener(t *testing.T) {
	var reached bool
	mgmt := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer mgmt.Close()
	ap := netip.MustParseAddrPort(mgmt.Listener.Addr().String())
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, mgmt.URL+"/v1/anything", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	defer mgmtaddr.Register(mgmtaddr.Register(int(ap.Port())))

	err := sendWebhook(context.Background(), redirect.URL, map[string]string{"text": "x"})
	if !errors.Is(err, mgmtaddr.ErrManagementListener) || reached {
		t.Fatalf("send = %v, reached %t; want the redirect refused", err, reached)
	}
}

// An ordinary receiver still gets the alert.
func TestAWebhookStillReachesItsReceiver(t *testing.T) {
	var got bool
	rcv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { got = true }))
	defer rcv.Close()
	if err := sendWebhook(context.Background(), rcv.URL, map[string]string{"text": "x"}); err != nil || !got {
		t.Fatalf("send = %v, received %t", err, got)
	}
}
