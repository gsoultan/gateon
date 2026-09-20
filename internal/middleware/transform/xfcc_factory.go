// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import "github.com/gsoultan/gateon/internal/middleware/kind"

func NewXFCC(cfg map[string]string) (kind.Middleware, error) {
	return XFCC(XFCCConfig{
		ForwardBy:      cfg["forward_by"] == "true",
		ForwardHash:    cfg["forward_hash"] == "true",
		ForwardSubject: cfg["forward_subject"] == "true",
		ForwardURI:     cfg["forward_uri"] == "true",
		ForwardDNS:     cfg["forward_dns"] == "true",
	}), nil
}
