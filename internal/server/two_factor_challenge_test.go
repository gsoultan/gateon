// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/pquerna/otp/totp"
)

// The second step of a sign-in, POST /v1/auth/2fa/verify, is served before
// authentication. It took an account id and a code and nothing else, so it did
// not know whether the password step had happened: an account id -- which any
// viewer reads in the audit log -- plus one current TOTP code or one recovery
// code was a whole administrator sign-in, with no password. These tests drive
// the management entrypoint's real chain (base handler, public-path list,
// handlers, ApiService, auth.Manager), because that chain is where the step is
// reached with no session: a test that hands the handler claims directly
// exercises a request production never makes.

const challengeTestPassword = "correct-horse"

// mgmtAnswer is what the sign-in endpoints answer with, read the way the
// dashboard reads it (protojson's lowerCamelCase).
type mgmtAnswer struct {
	Token                  string         `json:"token"`
	User                   *gateonv1.User `json:"user"`
	TwoFactorRequired      bool           `json:"twoFactorRequired"`
	TwoFactorSetupRequired bool           `json:"twoFactorSetupRequired"`
	TwoFactorChallenge     string         `json:"twoFactorChallenge"`
	Challenge              string         `json:"challenge"`
	Secret                 string         `json:"secret"`
	RecoveryCodes          []string       `json:"recoveryCodes"`
	ID                     string         `json:"id"`
	Success                bool           `json:"success"`
}

type mgmtClient struct {
	t *testing.T
	h http.Handler
}

func (c mgmtClient) do(method, path, body, bearer string) *httptest.ResponseRecorder {
	c.t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:5555"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	c.h.ServeHTTP(rr, req)
	return rr
}

func (c mgmtClient) decode(rr *httptest.ResponseRecorder) mgmtAnswer {
	c.t.Helper()
	var a mgmtAnswer
	if err := json.Unmarshal(rr.Body.Bytes(), &a); err != nil {
		c.t.Fatalf("decode %q: %v", rr.Body.String(), err)
	}
	return a
}

func (c mgmtClient) login(username, password string) mgmtAnswer {
	c.t.Helper()
	body := `{"username":"` + username + `","password":"` + password + `"}`
	rr := c.do(http.MethodPost, "/v1/login", body, "")
	if rr.Code != http.StatusOK {
		c.t.Fatalf("login %s: status %d: %s", username, rr.Code, rr.Body.String())
	}
	return c.decode(rr)
}

func (c mgmtClient) verify(id, code, challenge string) *httptest.ResponseRecorder {
	c.t.Helper()
	body := `{"id":"` + id + `","code":"` + code + `","challenge":"` + challenge + `"}`
	return c.do(http.MethodPost, "/v1/auth/2fa/verify", body, "")
}

// enrolled is an account with 2FA turned on through the dashboard's own
// self-service path, and what its owner holds.
type enrolled struct {
	id, secret string
	codes      []string
	session    string // issued before enrolment; still valid after it
}

// enrolRoot turns on 2FA for the seeded administrator the way the dashboard
// does: sign in, start setup with the password, verify a code from the new
// authenticator with the challenge setup handed back.
func enrolRoot(c mgmtClient) enrolled {
	c.t.Helper()
	signedIn := c.login("root", challengeTestPassword)
	if signedIn.Token == "" {
		c.t.Fatalf("root has no 2FA yet and should get a session: %+v", signedIn)
	}
	id := signedIn.User.GetId()
	rr := c.do(http.MethodPost, "/v1/auth/2fa/setup",
		`{"id":"`+id+`","password":"`+challengeTestPassword+`"}`, signedIn.Token)
	if rr.Code != http.StatusOK {
		c.t.Fatalf("setup: status %d: %s", rr.Code, rr.Body.String())
	}
	setup := c.decode(rr)
	code := totpNow(c.t, setup.Secret)
	if rr := c.verify(id, code, setup.Challenge); rr.Code != http.StatusOK {
		c.t.Fatalf("self-enrolment verify: status %d: %s", rr.Code, rr.Body.String())
	}
	return enrolled{id: id, secret: setup.Secret, codes: setup.RecoveryCodes, session: signedIn.Token}
}

func totpNow(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp: %v", err)
	}
	return code
}

// assertNoSession fails if rr signed anybody in.
func assertNoSession(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code == http.StatusOK {
		t.Errorf("second step answered 200 without proof of the password step: %s", rr.Body.String())
	}
	if strings.Contains(rr.Header().Get("Set-Cookie"), "gateon_session=v4.") {
		t.Errorf("second step set a session cookie: %s", rr.Header().Get("Set-Cookie"))
	}
	if strings.Contains(rr.Body.String(), "v4.local.") {
		t.Errorf("second step returned a token: %s", rr.Body.String())
	}
}

func assertChallengeRefused(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	assertNoSession(t, rr)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401: %s", rr.Code, rr.Body.String())
	}
}

func TestSecondStepWithoutChallengeIsRefused(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	c := mgmtClient{t: t, h: h}
	root := enrolRoot(c)

	t.Run("current TOTP code", func(t *testing.T) {
		assertChallengeRefused(t, mgmtClient{t: t, h: h}.verify(root.id, totpNow(t, root.secret), ""))
	})
	t.Run("recovery code", func(t *testing.T) {
		assertChallengeRefused(t, mgmtClient{t: t, h: h}.verify(root.id, root.codes[0], ""))
	})
	t.Run("garbage challenge", func(t *testing.T) {
		assertChallengeRefused(t, mgmtClient{t: t, h: h}.verify(root.id, totpNow(t, root.secret), "v4.local.garbage"))
	})
}

func TestSecondStepWithAnotherAccountsChallengeIsRefused(t *testing.T) {
	h, mgr, _ := buildManagementHandler(t)
	c := mgmtClient{t: t, h: h}
	root := enrolRoot(c)

	// bob is anyone who knows their own password and has a second step owed.
	bob := &gateonv1.User{Username: "bob", Password: "the-other-accounts-pw", Role: auth.RoleViewer}
	if err := mgr.UpsertUser(bob); err != nil {
		t.Fatal(err)
	}
	if err := mgr.SetTwoFactorPending(bob.Id, true); err != nil {
		t.Fatal(err)
	}
	bobs := c.login("bob", "the-other-accounts-pw")
	if !bobs.TwoFactorSetupRequired || bobs.TwoFactorChallenge == "" {
		t.Fatalf("bob's sign-in did not answer setup-required with a challenge: %+v", bobs)
	}
	assertChallengeRefused(t, c.verify(root.id, totpNow(t, root.secret), bobs.TwoFactorChallenge))
}

func TestSecondStepWithASessionAsChallengeIsRefused(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	c := mgmtClient{t: t, h: h}
	root := enrolRoot(c)
	// A live session of the very account: it proves the password was right
	// once, eight hours' worth, and is not a sign-in step.
	assertChallengeRefused(t, c.verify(root.id, totpNow(t, root.secret), root.session))
}

func TestChallengeIsNotASession(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	c := mgmtClient{t: t, h: h}
	enrolRoot(c)
	answer := c.login("root", challengeTestPassword)
	if !answer.TwoFactorRequired || answer.TwoFactorChallenge == "" {
		t.Fatalf("2FA sign-in did not answer with a challenge: %+v", answer)
	}
	if answer.Token != "" {
		t.Fatalf("the password step issued a session: %+v", answer)
	}
	for _, path := range []string{"/v1/me", "/v1/global"} {
		rr := c.do(http.MethodGet, path, "", answer.TwoFactorChallenge)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with the challenge as a bearer: status %d, want 401: %s", path, rr.Code, rr.Body.String())
		}
	}
}

func TestChallengeMadeStaleByPasswordChangeIsRefused(t *testing.T) {
	h, mgr, _ := buildManagementHandler(t)
	c := mgmtClient{t: t, h: h}
	root := enrolRoot(c)
	answer := c.login("root", challengeTestPassword)
	if answer.TwoFactorChallenge == "" {
		t.Fatalf("2FA sign-in did not answer with a challenge: %+v", answer)
	}
	if err := mgr.ChangePassword(root.id, "rotated-after-suspicion"); err != nil {
		t.Fatal(err)
	}
	assertChallengeRefused(t, c.verify(root.id, totpNow(t, root.secret), answer.TwoFactorChallenge))
}

// signedInAs asserts rr completed a sign-in, and that the session it issued
// carries role.
func signedInAs(c mgmtClient, rr *httptest.ResponseRecorder, role string) {
	c.t.Helper()
	if rr.Code != http.StatusOK {
		c.t.Fatalf("second step: status %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Set-Cookie"), "gateon_session=v4.") {
		c.t.Errorf("no session cookie: %q", rr.Header().Get("Set-Cookie"))
	}
	session := c.decode(rr).Token
	me := c.do(http.MethodGet, "/v1/me", "", session)
	if me.Code != http.StatusOK || c.decode(me).User.GetRole() != role {
		c.t.Errorf("GET /v1/me with the new session: status %d, body %s, want role %q", me.Code, me.Body.String(), role)
	}
}

func TestPasswordThenChallengeThenCodeSignsIn(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	c := mgmtClient{t: t, h: h}
	root := enrolRoot(c)

	t.Run("TOTP", func(t *testing.T) {
		c := mgmtClient{t: t, h: h}
		answer := c.login("root", challengeTestPassword)
		signedInAs(c, c.verify(root.id, totpNow(t, root.secret), answer.TwoFactorChallenge), auth.RoleAdmin)
	})
	t.Run("recovery code", func(t *testing.T) {
		c := mgmtClient{t: t, h: h}
		answer := c.login("root", challengeTestPassword)
		signedInAs(c, c.verify(root.id, root.codes[1], answer.TwoFactorChallenge), auth.RoleAdmin)
	})
}

// TestMandatedEnrolmentSignsInWithTheLoginChallenge is the flow an account an
// administrator required 2FA for goes through: the password answers "setup
// required" with a challenge, enrolment re-proves the password and hands out
// the secret, and the first code -- with the login's challenge -- signs in.
func TestMandatedEnrolmentSignsInWithTheLoginChallenge(t *testing.T) {
	h, mgr, _ := buildManagementHandler(t)
	c := mgmtClient{t: t, h: h}
	carol := &gateonv1.User{Username: "carol", Password: "her-own-passphrase", Role: auth.RoleOperator}
	if err := mgr.UpsertUser(carol); err != nil {
		t.Fatal(err)
	}
	if err := mgr.SetTwoFactorPending(carol.Id, true); err != nil {
		t.Fatal(err)
	}
	answer := c.login("carol", "her-own-passphrase")
	if !answer.TwoFactorSetupRequired || answer.TwoFactorChallenge == "" {
		t.Fatalf("mandated sign-in did not answer setup-required with a challenge: %+v", answer)
	}
	rr := c.do(http.MethodPost, "/v1/auth/2fa/enroll", `{"username":"carol","password":"her-own-passphrase"}`, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("enroll: status %d: %s", rr.Code, rr.Body.String())
	}
	enrol := c.decode(rr)
	signedInAs(c, c.verify(enrol.ID, totpNow(t, enrol.Secret), answer.TwoFactorChallenge), auth.RoleOperator)
}

// TestRefusedChallengesDoNotLockTheAccount: the lockout counts guesses at a
// credential. A request with no valid challenge is not a guess at anything the
// account owns -- it is anyone who knows an id -- so counting it would hand
// every such caller a way to lock an administrator out by id.
func TestRefusedChallengesDoNotLockTheAccount(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	c := mgmtClient{t: t, h: h}
	root := enrolRoot(c)
	for range auth.MaxFailedAttempts + 1 {
		assertChallengeRefused(t, c.verify(root.id, "000000", ""))
	}
	answer := c.login("root", challengeTestPassword)
	if !answer.TwoFactorRequired {
		t.Fatalf("sign-in after refused second steps: %+v", answer)
	}
	signedInAs(c, c.verify(root.id, totpNow(t, root.secret), answer.TwoFactorChallenge), auth.RoleAdmin)
}

// TestSecondStepHasNoRPCWayAround pins that the second step has no Connect or
// gRPC procedure: it exists only as POST /v1/auth/2fa/verify. A procedure
// added later is not public (publicAuthPaths is exact-match) and would reach
// the same ApiService.Verify2FA, which carries the challenge to the manager.
func TestSecondStepHasNoRPCWayAround(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	c := mgmtClient{t: t, h: h}
	root := enrolRoot(c)
	body := `{"id":"` + root.id + `","code":"` + totpNow(t, root.secret) + `"}`
	assertNoSession(t, c.do(http.MethodPost, "/gateon.v1.ApiService/Verify2FA", body, ""))
}
