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
		if f.globalStore != nil {
			global := f.globalStore.Get(nil)
			if global != nil && global.Waf != nil && global.Waf.BotManagement != nil && global.Waf.BotManagement.SecretKey != "" {
				secret = global.Waf.BotManagement.SecretKey
			}
		}
	}
	if secret == "" {
		secret = "gateon-default-secret"
	}

	return BotManagement(BotManagementConfig{
		Enabled:                 enabled,
		EnableJSChallenge:       enableJS,
		EnableBrowserIntegrity:  enableIntegrity,
		ChallengeTimeoutSeconds: timeout,
		SecretKey:               secret,
		RouteID:                 cfg["_route_id"],
	}), nil
}
