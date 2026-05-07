package middleware

import (
	"strconv"
)

func (f *Factory) createBotManagement(cfg map[string]string) (Middleware, error) {
	enabled := cfg["enabled"] == "true"
	enableJS := cfg["enable_js_challenge"] == "true"
	enableIntegrity := cfg["enable_browser_integrity"] == "true"
	timeout, _ := strconv.Atoi(cfg["challenge_timeout"])
	if timeout == 0 {
		timeout = 3600 // Default 1 hour
	}
	secret := cfg["secret_key"]
	if secret == "" {
		secret = "gateon-default-secret" // Should be from global config in production
	}

	return BotManagement(BotManagementConfig{
		Enabled:                 enabled,
		EnableJSChallenge:       enableJS,
		EnableBrowserIntegrity:  enableIntegrity,
		ChallengeTimeoutSeconds: timeout,
		SecretKey:               secret,
	}), nil
}
