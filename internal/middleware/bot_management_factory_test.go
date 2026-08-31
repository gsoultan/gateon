// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestFallbackSecretIsNotAPublishedConstant is the regression guard. SecretKey
// is the HMAC key behind verifyChallengeToken, so a value visible in the source
// let anyone compute a valid token for any user agent and address and walk past
// both the JS challenge and the browser integrity check.
func TestFallbackSecretIsNotAPublishedConstant(t *testing.T) {
	got := fallbackBotSecret()

	if got == "gateon-default-secret" {
		t.Fatal("the published default secret is still in use; bot management is bypassable")
	}
	if len(got) < 32 {
		t.Errorf("fallback secret is %d chars, too short to be a 256-bit key", len(got))
	}
	if strings.TrimSpace(got) == "" {
		t.Fatal("fallback secret is empty, which would make every token verify trivially")
	}
}

// Every route in a process must agree, or a client would be re-challenged on
// each route it touches.
func TestFallbackSecretIsStableWithinTheProcess(t *testing.T) {
	// Assigned rather than compared inline: staticcheck reads f() != f() as a
	// mistake (SA4000), and here the repeated call is the whole point.
	first := fallbackBotSecret()
	second := fallbackBotSecret()
	if first != second {
		t.Fatal("fallback secret changes between calls; tokens would never verify")
	}
}

// Absence and "false" have to be distinguished. Treating an unset key as false
// is what made the global toggles inert: routes omit most keys, so a global
// setting could never reach any of them.
func TestGlobalSettingsApplyOnlyWhenTheRouteIsSilent(t *testing.T) {
	if got := boolSetting(map[string]string{}, "enable_js_challenge", true); !got {
		t.Error("a global true did not apply to a route that never mentions the key")
	}
	if got := boolSetting(map[string]string{"enable_js_challenge": "false"}, "enable_js_challenge", true); got {
		t.Error("an explicit route false was overridden by the global value")
	}
	if got := boolSetting(map[string]string{"enable_js_challenge": "true"}, "enable_js_challenge", false); !got {
		t.Error("an explicit route true was not honoured")
	}
	if got := boolSetting(map[string]string{}, "enable_js_challenge", false); got {
		t.Error("a global false became true")
	}
}

// GetX on a nil message is the generated nil-safe accessor; the factory relies
// on that so a missing global block behaves as all-defaults rather than panicking.
func TestNilGlobalBlockIsTreatedAsUnset(t *testing.T) {
	var g *gateonv1.BotManagementConfig
	if g.GetEnableJsChallenge() || g.GetSecretKey() != "" || g.GetChallengeTimeoutSeconds() != 0 {
		t.Fatal("nil global block did not read as unset")
	}
	if got := boolSetting(map[string]string{}, "enabled", g.GetEnabled()); got {
		t.Error("nil global block enabled bot management")
	}
}

// TestForgedTokenFromThePublishedSecretIsRejected is the guard that matters.
//
// Asserting on fallbackBotSecret alone still passes if createBotManagement goes
// back to using a constant — that tests the helper, not the wiring. This drives
// a request through the middleware the factory actually builds, carrying a token
// forged with the secret that used to be compiled in, and requires that it does
// not get through.
func TestForgedTokenFromThePublishedSecretIsRejected(t *testing.T) {
	const publishedSecret = "gateon-default-secret"
	const ua = "Mozilla/5.0 (forged)"

	f := &Factory{}
	mw, err := f.createBotManagement(map[string]string{
		"enabled":             "true",
		"enable_js_challenge": "true",
	})
	if err != nil {
		t.Fatalf("createBotManagement: %v", err)
	}

	passedThrough := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { passedThrough = true }))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", ua)
	req.RemoteAddr = "203.0.113.9:1234"
	clientIP := request.GetClientIP(req, false)
	req.AddCookie(&http.Cookie{
		Name:  ChallengeCookieName,
		Value: GenerateChallengeSeed(publishedSecret, ua, clientIP),
	})

	h.ServeHTTP(httptest.NewRecorder(), req)

	if passedThrough {
		t.Fatal("a token forged with the published default secret was accepted; " +
			"bot management is bypassable by anyone who reads the source")
	}
}
