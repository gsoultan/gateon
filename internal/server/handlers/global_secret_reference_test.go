// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
)

// TestGlobalSettingsRoundTripKeepsSecretReferences is the Settings page's save:
// read GET /v1/global as someone who may write it, change nothing, PUT it back.
//
// global.json names its session key and database URL with $env: references so
// the secrets themselves live in the service manager, not in the file. The
// registry resolves them on load, and GET handed the resolved values to the
// dashboard -- so the dashboard held the real secrets, and its save wrote them
// back as plaintext, replacing the references. After one unrelated settings
// change the file carried the database password and the signing key in the
// clear (or pinned under the encryption key), and rotating the variable no
// longer changed anything.
func TestGlobalSettingsRoundTripKeepsSecretReferences(t *testing.T) {
	const (
		pasetoRef    = "$env:GATEON_TEST_PASETO_REF_5521"
		pasetoValue  = "resolved-paseto-secret-32-bytes!"
		dbURLRef     = "$env:GATEON_TEST_DB_URL_REF_5521"
		dbURLValue   = "postgres://gateon:s3cr3t-db-pass@db.internal/gateon"
		roundTripped = `"pasetoSecret"`
	)
	t.Setenv("GATEON_TEST_PASETO_REF_5521", pasetoValue)
	t.Setenv("GATEON_TEST_DB_URL_REF_5521", dbURLValue)

	path := filepath.Join(t.TempDir(), "global.json")
	stored := `{"auth": {"enabled": true, "paseto_secret": "` + pasetoRef + `", "database_url": "` + dbURLRef + `"},
  "waf": {"enabled": true}}`
	if err := os.WriteFile(path, []byte(stored), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := config.NewGlobalRegistry(path)
	if got := reg.Get(context.Background()).GetAuth().GetPasetoSecret(); got != pasetoValue {
		t.Fatalf("precondition: the live config holds %q, want the resolved secret", got)
	}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, &globalsAPI{store: reg}, &Deps{})

	read := getGlobalAs(t, mux, auth.RoleAdmin).Body.String()
	if !strings.Contains(read, roundTripped) {
		t.Fatalf("precondition: GET did not include the auth block: %s", read)
	}
	for _, secret := range []string{pasetoValue, "s3cr3t-db-pass"} {
		if strings.Contains(read, secret) {
			t.Errorf("GET /v1/global handed the resolved secret %q to the dashboard; it should see the reference", secret)
		}
	}

	req := httptest.NewRequest(http.MethodPut, "/v1/global", strings.NewReader(read))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "admin-1", Username: "admin", Role: auth.RoleAdmin}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT /v1/global answered %d: %s", rr.Code, rr.Body.String())
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{pasetoRef, dbURLRef} {
		if !strings.Contains(string(onDisk), ref) {
			t.Errorf("the reference %s is gone from global.json after an unchanged save; on disk:\n%s", ref, onDisk)
		}
	}
	for _, secret := range []string{pasetoValue, "s3cr3t-db-pass"} {
		if strings.Contains(string(onDisk), secret) {
			t.Errorf("global.json now holds the resolved secret %q in the clear", secret)
		}
	}
	if got := reg.Get(context.Background()).GetAuth().GetPasetoSecret(); got != pasetoValue {
		t.Errorf("after the save the live config holds %q, want the resolved secret still in force", got)
	}
}
