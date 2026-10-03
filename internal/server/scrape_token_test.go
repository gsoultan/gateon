// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
)

// issueScrapeToken creates a metrics:read token as the administrator, over
// REST, and returns its id and secret.
func issueScrapeToken(t *testing.T, c mgmtClient, adminToken string) (id, secret string) {
	t.Helper()
	rr := c.do(http.MethodPost, "/v1/api-tokens", `{"name":"prometheus","scopes":["metrics:read"]}`, adminToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /v1/api-tokens as admin: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		Token struct {
			ID string `json:"id"`
		} `json:"token"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil || created.Secret == "" || created.Token.ID == "" {
		t.Fatalf("decode %q: %v", rr.Body.String(), err)
	}
	return created.Token.ID, created.Secret
}

func sessionFor(t *testing.T, c mgmtClient, username, password string) string {
	t.Helper()
	a := c.login(username, password)
	if a.Token == "" {
		t.Fatalf("sign-in as %s gave no session", username)
	}
	return a.Token
}

// TestAScrapeTokenReadsMetricsAndNothingElse is ADR 0050's scrape credential:
// /metrics accepted only an eight-hour user session, so Prometheus needed a
// viewer account and a script re-signing in on a timer. A token an
// administrator issues with metrics:read is accepted there -- and is not a
// session anywhere else, on any transport.
func TestAScrapeTokenReadsMetricsAndNothingElse(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	c := mgmtClient{t: t, h: h}
	admin := sessionFor(t, c, "root", "correct-horse")
	_, secret := issueScrapeToken(t, c, admin)

	if rr := c.do(http.MethodGet, "/metrics", "", secret); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "# HELP") {
		t.Fatalf("GET /metrics with the scrape token: %d %.200s, want 200 and the exposition", rr.Code, rr.Body.String())
	}
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/status", ""},
		{http.MethodGet, "/v1/global", ""},
		{http.MethodGet, "/v1/api-tokens", ""},
		{http.MethodPost, "/v1/api-tokens", `{"name":"escalate","scopes":["metrics:read"]}`},
		{http.MethodPost, "/" + gateonv1connect.ApiServiceName + "/GetStatus", "{}"},
		{http.MethodGet, "/v1/audit/verify", ""},
		// Served without a permission check once past authentication: only
		// the session check stands between a token and it.
		{http.MethodGet, "/v1/openapi.json", ""},
	} {
		if rr := c.do(tc.method, tc.path, tc.body, secret); rr.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with the scrape token: %d %.200s, want 401", tc.method, tc.path, rr.Code, rr.Body.String())
		}
	}
	if rr := c.do(http.MethodGet, "/metrics", "", ""); rr.Code != http.StatusUnauthorized {
		t.Errorf("GET /metrics with no credential: %d, want 401", rr.Code)
	}
	if rr := c.do(http.MethodGet, "/metrics", "", admin); rr.Code != http.StatusOK {
		t.Errorf("GET /metrics with a session still: %d, want 200", rr.Code)
	}
}

// TestARevokedScrapeTokenStopsAtOnce, and the list never shows a secret.
func TestARevokedScrapeTokenStopsAtOnce(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	c := mgmtClient{t: t, h: h}
	admin := sessionFor(t, c, "root", "correct-horse")
	id, secret := issueScrapeToken(t, c, admin)

	list := c.do(http.MethodGet, "/v1/api-tokens", "", admin)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), id) || strings.Contains(list.Body.String(), secret) {
		t.Fatalf("GET /v1/api-tokens: %d %s; want the token listed without its secret", list.Code, list.Body.String())
	}
	if rr := c.do(http.MethodDelete, "/v1/api-tokens/"+id, "", admin); rr.Code != http.StatusOK {
		t.Fatalf("DELETE /v1/api-tokens/%s: %d %s", id, rr.Code, rr.Body.String())
	}
	if rr := c.do(http.MethodGet, "/metrics", "", secret); rr.Code != http.StatusUnauthorized {
		t.Errorf("GET /metrics with a revoked token: %d, want 401", rr.Code)
	}
	if rr := c.do(http.MethodDelete, "/v1/api-tokens/"+id, "", admin); rr.Code == http.StatusOK {
		t.Errorf("revoking it twice answered 200")
	}
}

// TestOnlyAnAdministratorManagesScrapeTokens: an operator can read
// everything but users, and a token is a credential, so neither an operator
// nor a viewer may list, issue or revoke one -- over REST, Connect or gRPC.
func TestOnlyAnAdministratorManagesScrapeTokens(t *testing.T) {
	h, mgr, _ := buildManagementHandler(t)
	c := mgmtClient{t: t, h: h}
	for _, role := range []string{auth.RoleOperator, auth.RoleViewer} {
		name := role + "-account"
		if err := mgr.UpsertUser(&gateonv1.User{Username: name, Password: "a-long-enough-pass", Role: role}); err != nil {
			t.Fatal(err)
		}
		session := sessionFor(t, c, name, "a-long-enough-pass")
		for _, tc := range []struct{ method, path, body string }{
			{http.MethodGet, "/v1/api-tokens", ""},
			{http.MethodPost, "/v1/api-tokens", `{"name":"mine","scopes":["metrics:read"]}`},
			{http.MethodPost, "/" + gateonv1connect.ApiServiceName + "/ListApiTokens", "{}"},
			{http.MethodPost, "/" + gateonv1connect.ApiServiceName + "/CreateApiToken", `{"name":"mine","scopes":["metrics:read"]}`},
			{http.MethodGet, "/v1/audit/verify", ""},
			{http.MethodPost, "/" + gateonv1connect.ApiServiceName + "/VerifyAuditChain", "{}"},
		} {
			if rr := c.do(tc.method, tc.path, tc.body, session); rr.Code != http.StatusForbidden {
				t.Errorf("%s: %s %s: %d %.200s, want 403", role, tc.method, tc.path, rr.Code, rr.Body.String())
			}
		}
	}
}
