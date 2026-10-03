// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/server/mgmtorigin"
)

// /v1/logs streams the system log over a WebSocket. Its upgrader accepted any
// Origin, and a browser lets a page on any site open a WebSocket and read what
// comes back, sending the cookie whenever the target is same-site. So a page on
// another port of the dashboard's address could read the gateway's log with the
// admin's session (review M9, ADR 0041).

// logsServer serves the diagnostics handlers with a verifier that accepts one
// admin token, and returns the ws:// URL of /v1/logs carrying it.
func logsServer(t *testing.T, origins *mgmtorigin.Policy) (string, string) {
	t.Helper()
	mux := http.NewServeMux()
	registerDiagnosticHandlers(mux, nil, &Deps{
		AuthManager: testTokenVerifier{token: "admin-token", claims: &auth.Claims{Role: auth.RoleAdmin}},
		MgmtOrigins: origins,
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/logs?auth=admin-token", srv.URL
}

// dialLogs opens the log stream with the given request headers and returns the
// handshake's status code.
func dialLogs(t *testing.T, wsURL string, hdr http.Header) int {
	t.Helper()
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if conn != nil {
		_ = conn.Close()
	}
	if resp == nil {
		t.Fatalf("handshake got no response: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestLogsHandshakeFromAForeignOriginIsRefused(t *testing.T) {
	wsURL, _ := logsServer(t, nil)
	for _, hdr := range []http.Header{
		{"Origin": {"https://evil.example"}},
		{"Origin": {"https://evil.example"}, "Sec-Fetch-Site": {"cross-site"}},
		{"Origin": {"http://127.0.0.1:9"}, "Sec-Fetch-Site": {"same-site"}},
	} {
		if code := dialLogs(t, wsURL, hdr); code != http.StatusForbidden {
			t.Errorf("handshake with %v = %d, want 403: a foreign page opened the system log with the admin's session",
				hdr, code)
		}
	}
}

func TestLogsHandshakeFromTheManagementOriginIsAccepted(t *testing.T) {
	wsURL, httpURL := logsServer(t, mgmtorigin.New([]string{"https://dash.example"}))
	for _, hdr := range []http.Header{
		{"Origin": {httpURL}},
		{"Origin": {httpURL}, "Sec-Fetch-Site": {"same-origin"}},
		{"Origin": {"https://dash.example"}, "Sec-Fetch-Site": {"cross-site"}}, // configured CORS origin
		nil, // a client that is not a browser sends no Origin
	} {
		if code := dialLogs(t, wsURL, hdr); code != http.StatusSwitchingProtocols {
			t.Errorf("handshake with %v = %d, want 101", hdr, code)
		}
	}
}
