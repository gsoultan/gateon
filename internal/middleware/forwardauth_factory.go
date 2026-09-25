// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

func (f *Factory) createForwardAuth(cfg map[string]string) (Middleware, error) {
	maxBody, err := kind.ParseIntStrict(cfg["max_body_size"], 1024*1024)
	if err != nil || maxBody < 0 {
		if err == nil {
			err = strconv.ErrRange
		}
		return nil, kind.CfgError("max_body_size", cfg["max_body_size"], err)
	}
	// Strict, as every other factory reads booleans: a value that is present
	// and not a boolean refuses the build. These read anything but "true", "1"
	// or "yes" as false, and a malformed body size as the 1 MiB default.
	bools := kind.NewBoolFields(cfg)
	forwardCfg := ForwardAuthConfig{
		Address:               strings.TrimSpace(cfg["address"]),
		TrustForwardHeader:    bools.Get("trust_forward_header", false),
		AuthResponseHeaders:   kind.ParseListStrict(cfg["auth_response_headers"]),
		AuthRequestHeaders:    kind.ParseListStrict(cfg["auth_request_headers"]),
		ForwardBody:           bools.Get("forward_body", false),
		PreserveRequestMethod: bools.Get("preserve_request_method", false),
		MaxBodySize:           int64(maxBody),
		TLSInsecureSkipVerify: bools.Get("tls_insecure_skip_verify", false),
	}
	if err := bools.Err(); err != nil {
		return nil, err
	}
	return ForwardAuth(forwardCfg)
}
