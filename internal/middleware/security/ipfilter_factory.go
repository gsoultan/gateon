// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
)

func NewIPFilter(cfg map[string]string) (kind.Middleware, error) {
	allowList := kind.ParseListStrict(cfg["allow_list"])
	denyList := kind.ParseListStrict(cfg["deny_list"])
	trust := request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"])
	clientIP := func(r *http.Request) string { return request.GetClientIP(r, trust) }
	return IPFilterWithClientIP(allowList, denyList, clientIP), nil
}
