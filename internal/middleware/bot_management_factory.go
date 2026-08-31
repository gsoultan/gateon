// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// generatedBotSecret is the per-process fallback challenge key.
//
// It replaces a compile-time constant. SecretKey is the HMAC key behind
// verifyChallengeToken, so a value visible in the source let anyone compute a
// valid token for any user agent and address and walk past the JS challenge and
// the browser integrity check — bot management was bypassable by reading the
// repository.
//
// Generated once per process so every route agrees within an instance. The
// consequence, which the log names, is that tokens do not survive a restart and
// are not shared between instances, so clients are challenged again. That is a
// real cost and the reason to configure a secret; it is not a reason to keep
// publishing one.
var (
	generatedBotSecretOnce sync.Once
	generatedBotSecret     string
)

func fallbackBotSecret() string {
	generatedBotSecretOnce.Do(func() {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			// crypto/rand failing is not survivable for a security control.
			logger.L.LogError("cannot generate a bot-challenge secret; disabling challenge issuance",
				"error", err)
			return
		}
		generatedBotSecret = hex.EncodeToString(b)
		logger.L.LogWarn("no waf.bot_management.secret_key configured; generated a random one for this " +
			"process. Challenge tokens will not survive a restart and are not shared between instances, " +
			"so clients will be re-challenged. Set a secret to avoid that.")
	})
	return generatedBotSecret
}

// globalBotManagement returns the global bot-management settings, or nil.
func (f *Factory) globalBotManagement() *gateonv1.BotManagementConfig {
	if f.globalStore == nil {
		return nil
	}
	global := f.globalStore.Get(context.TODO())
	if global == nil || global.Waf == nil {
		return nil
	}
	return global.Waf.BotManagement
}

// boolSetting reads a per-route flag, falling back to the global value only when
// the route does not mention the key at all.
//
// Absence and "false" are deliberately distinguished. Treating an unset key as
// false is what made the global toggles inert: every route omits most keys, so a
// global setting could never apply to any of them.
func boolSetting(cfg map[string]string, key string, global bool) bool {
	if v, ok := cfg[key]; ok {
		return v == "true"
	}
	return global
}

// resolveBotSecret picks the HMAC key for challenge tokens: the route's own, the
// global one, or a generated fallback. It never returns a constant.
func (f *Factory) resolveBotSecret(cfg map[string]string, g *gateonv1.BotManagementConfig) string {
	if s := cfg["secret_key"]; s != "" {
		return s
	}
	if s := g.GetSecretKey(); s != "" {
		return s
	}
	return fallbackBotSecret()
}

func (f *Factory) createBotManagement(cfg map[string]string) (Middleware, error) {
	g := f.globalBotManagement()

	enabled := boolSetting(cfg, "enabled", g.GetEnabled())
	enableJS := boolSetting(cfg, "enable_js_challenge", g.GetEnableJsChallenge())
	enableIntegrity := boolSetting(cfg, "enable_browser_integrity", g.GetEnableBrowserIntegrity())

	timeout, _ := strconv.Atoi(cfg["challenge_timeout"])
	if timeout == 0 {
		timeout = int(g.GetChallengeTimeoutSeconds())
	}
	if timeout == 0 {
		timeout = 3600 // Default 1 hour
	}

	secret := f.resolveBotSecret(cfg, g)

	return BotManagement(BotManagementConfig{
		Enabled:                 enabled,
		EnableJSChallenge:       enableJS,
		EnableBrowserIntegrity:  enableIntegrity,
		ChallengeTimeoutSeconds: timeout,
		SecretKey:               secret,
		RouteID:                 cfg["_route_id"],
	}), nil
}
