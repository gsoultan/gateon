// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"errors"
	"net/url"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
)

func NewXFCC(cfg map[string]string) (kind.Middleware, error) {
	c := XFCCConfig{
		ForwardBy:      cfg["forward_by"] == "true",
		By:             strings.TrimSpace(cfg["by"]),
		ForwardHash:    cfg["forward_hash"] == "true",
		ForwardSubject: cfg["forward_subject"] == "true",
		ForwardURI:     cfg["forward_uri"] == "true",
		ForwardDNS:     cfg["forward_dns"] == "true",
	}
	if c.ForwardBy && checkXFCCBy(c.By) != nil {
		// A save is refused (CheckXFCCSave); a stored config from before that
		// still builds, without the pair, so the route keeps its client-cert
		// header and the strip of a client's own copy.
		logger.L.LogWarn("xfcc: forward_by is on with no valid by URI; no By pair is forwarded",
			"middleware", cfg[kind.MiddlewareIDKey], "by", c.By)
	}
	return XFCC(c), nil
}

// CheckXFCCSave refuses an xfcc config that would save a switch doing nothing:
// Forward By with no identity to name (ADR 0046).
func CheckXFCCSave(cfg map[string]string) error {
	if cfg["forward_by"] != "true" {
		return nil
	}
	if err := checkXFCCBy(strings.TrimSpace(cfg["by"])); err != nil {
		return kind.CfgError("by", cfg["by"], err)
	}
	return nil
}

// checkXFCCBy accepts an absolute URI, which is what Envoy's By names: the URI
// SAN of the proxy's certificate, such as spiffe://example.org/gateway.
func checkXFCCBy(by string) error {
	if by == "" {
		return errors.New("forward_by is on and by is empty; set by to the URI this gateway forwards as By " +
			"(the URI SAN of its certificate, e.g. spiffe://example.org/gateway), or turn Forward By off")
	}
	u, err := url.Parse(by)
	if err != nil || u.Scheme == "" {
		return errors.New("by must be an absolute URI, e.g. spiffe://example.org/gateway")
	}
	return nil
}
