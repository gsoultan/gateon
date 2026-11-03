// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"fmt"
	"os"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

// NewTurnstile builds the turnstile middleware from its dashboard config.
// verifyURL is where tokens are checked, "" for Cloudflare; it is not part of
// the config, so an operator cannot point verification at a server of their own.
func NewTurnstile(cfg map[string]string, verifyURL string) (kind.Middleware, error) {
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
		VerifyURL:  verifyURL,
	}), nil
}
