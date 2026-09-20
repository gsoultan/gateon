// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

func NewCompress(cfg map[string]string) (kind.Middleware, error) {
	compressCfg := CompressConfig{
		MinResponseBodyBytes: kind.ParsePositiveInt(cfg["min_response_body_bytes"], 1024),
		ExcludedContentTypes: kind.ParseListStrict(cfg["excluded_content_types"]),
		IncludedContentTypes: kind.ParseListStrict(cfg["included_content_types"]),
		MaxBufferBytes:       kind.ParsePositiveInt(cfg["max_buffer_bytes"], 10*1024*1024),
		Algorithm:            strings.TrimSpace(cfg["algorithm"]),
	}
	return CompressWithConfig(compressCfg), nil
}
