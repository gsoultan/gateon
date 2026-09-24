// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// configuredGatewayAPI is a gateway whose setup has completed: an
// administrator exists, so Setup refuses exactly as ApiService.Setup does.
type configuredGatewayAPI struct {
	GlobalAndAuthAPI
	globals config.GlobalConfigStore
}

func (c *configuredGatewayAPI) GetGlobals() config.GlobalConfigStore { return c.globals }

func (c *configuredGatewayAPI) IsSetupRequired(context.Context, *gateonv1.IsSetupRequiredRequest) (*gateonv1.IsSetupRequiredResponse, error) {
	return &gateonv1.IsSetupRequiredResponse{Required: false}, nil
}

func (c *configuredGatewayAPI) Setup(context.Context, *gateonv1.SetupRequest) (*gateonv1.SetupResponse, error) {
	return &gateonv1.SetupResponse{Success: false, Error: "setup already completed"}, nil
}

// TestSetupCannotRepointTheDatabasesOnceSetupIsComplete sends the first-run
// wizard's request to a gateway that is already set up, the way anyone who
// can reach the management port can: /v1/setup skips authentication for the
// life of the process.
//
// The handler validated and persisted the caller's database_url and
// logging_database_url into global config before Setup's own "already
// completed" check ran. An unauthenticated request could therefore repoint the
// authentication database — whose users the gateway trusts on its next start —
// and the audit database at a server the caller controls, and open a
// connection to an arbitrary DSN on the way.
func TestSetupCannotRepointTheDatabasesOnceSetupIsComplete(t *testing.T) {
	dir := t.TempDir()
	globals := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	legit := filepath.Join(dir, "gateon.db")
	gc := globals.Get(t.Context())
	gc.Auth.DatabaseUrl = legit
	if err := globals.Update(t.Context(), gc); err != nil {
		t.Fatalf("seed globals: %v", err)
	}

	attacker := filepath.Join(dir, "attacker.db")
	body := `{"admin_username":"eve","admin_password":"pw","paseto_secret":"` + strings.Repeat("k", 32) +
		`","database_url":` + strconv.Quote(attacker) + `,"logging_database_url":` + strconv.Quote(attacker) + `}`
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, &configuredGatewayAPI{globals: globals}, &Deps{})
	req := httptest.NewRequest(http.MethodPost, "/v1/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(httptest.NewRecorder(), req)

	after := globals.Get(t.Context())
	if got := after.GetAuth().GetDatabaseUrl(); got != legit {
		t.Errorf("auth database is now %q, want %q: an unauthenticated setup call repointed it", got, legit)
	}
	if got := after.GetAudit().GetDatabaseUrl(); got != "" {
		t.Errorf("audit database is now %q, want it untouched", got)
	}
	if _, err := os.Stat(attacker); err == nil {
		t.Error("the handler opened the caller-supplied database on a configured gateway")
	}
}

// unknownSetupStateAPI cannot tell whether setup has happened, the state a
// failing database puts IsSetupRequired in.
type unknownSetupStateAPI struct{ configuredGatewayAPI }

func (u *unknownSetupStateAPI) IsSetupRequired(context.Context, *gateonv1.IsSetupRequiredRequest) (*gateonv1.IsSetupRequiredResponse, error) {
	return nil, errors.New("database unreachable")
}

// TestSetupRefusesWhenTheSetupStateIsUnknown keeps "I could not tell" from
// reading as "go ahead": the same unauthenticated request must not be able to
// write global config while the gateway cannot say whether it is configured.
func TestSetupRefusesWhenTheSetupStateIsUnknown(t *testing.T) {
	dir := t.TempDir()
	globals := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	attacker := filepath.Join(dir, "attacker.db")
	body := `{"paseto_secret":"` + strings.Repeat("k", 32) + `","database_url":` + strconv.Quote(attacker) + `}`
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, &unknownSetupStateAPI{configuredGatewayAPI{globals: globals}}, &Deps{})
	req := httptest.NewRequest(http.MethodPost, "/v1/setup", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403 when the setup state cannot be determined", rec.Code)
	}
	if got := globals.Get(t.Context()).GetAuth().GetDatabaseUrl(); got == attacker {
		t.Error("the auth database was repointed while the setup state was unknown")
	}
}
