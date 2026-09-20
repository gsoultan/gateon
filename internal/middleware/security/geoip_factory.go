// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
)

func NewGeoIP(cfg map[string]string) (kind.Middleware, error) {
	return GeoIP(GeoIPConfig{
		DBPath:          strings.TrimSpace(cfg["db_path"]),
		AllowCountries:  kind.ParseListStrict(cfg["allow_countries"]),
		DenyCountries:   kind.ParseListStrict(cfg["deny_countries"]),
		TrustCloudflare: request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"]),
	})
}
