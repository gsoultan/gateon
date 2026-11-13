// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/auth/authtest"
)

// signInOverREST runs a whole sign-in through the management plane's REST
// endpoints, as the sign-in page does: the password, the first-time enrolment
// when the account has no second factor (every account must have one,
// ADR 0087), and a code. send carries one POST and returns its answer. It
// returns the answer to the step that signed in, which carries the session
// cookie and, for a client that is not a browser, the token.
func signInOverREST(t *testing.T, send func(path, body string) *httptest.ResponseRecorder, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	creds := `{"username":"` + username + `","password":"` + password + `"}`
	rr := send("/v1/login", creds)
	if rr.Code != http.StatusOK {
		t.Fatalf("signing in as %s: status %d: %s", username, rr.Code, rr.Body.String())
	}
	var step mgmtAnswer
	if err := json.Unmarshal(rr.Body.Bytes(), &step); err != nil {
		t.Fatalf("decode %q: %v", rr.Body.String(), err)
	}
	id, secret := step.User.GetId(), authtest.Secret(step.User.GetId())
	if step.TwoFactorSetupRequired {
		rr = send("/v1/auth/2fa/enroll", creds)
		var enrol mgmtAnswer
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &enrol) != nil {
			t.Fatalf("enrolling %s: status %d: %s", username, rr.Code, rr.Body.String())
		}
		id, secret = enrol.ID, enrol.Secret
		authtest.Remember(id, secret)
	}
	if secret == "" {
		t.Fatalf("signing in as %s: no second factor to answer with: %+v", username, step)
	}
	code, err := authtest.Code(secret)
	if err != nil {
		t.Fatal(err)
	}
	rr = send("/v1/auth/2fa/verify", `{"id":"`+id+`","code":"`+code+`","challenge":"`+step.TwoFactorChallenge+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("second step for %s: status %d: %s", username, rr.Code, rr.Body.String())
	}
	return rr
}
