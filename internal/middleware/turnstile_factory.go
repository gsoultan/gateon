package middleware

import (
	"fmt"
	"os"
	"strings"
)

func (f *Factory) createTurnstile(cfg map[string]string) (Middleware, error) {
	secret := strings.TrimSpace(cfg["secret"])
	if secret == "" {
		secret = os.Getenv("GATEON_TURNSTILE_SECRET")
	}
	if secret == "" {
		return nil, fmt.Errorf("turnstile requires secret or GATEON_TURNSTILE_SECRET env")
	}
	headerName := cfg["header"]
	if headerName == "" {
		headerName = "CF-Turnstile-Response"
	}
	methods := cfg["methods"]
	if methods == "" {
		methods = "POST,PUT,PATCH,DELETE"
	}
	return Turnstile(TurnstileConfig{
		Secret:     secret,
		HeaderName: strings.TrimSpace(headerName),
		Methods:    strings.Split(methods, ","),
	}), nil
}
