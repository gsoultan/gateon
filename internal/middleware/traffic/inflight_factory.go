// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"fmt"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

// NewInflightReq caps concurrent requests: per client address by default
// (per_ip, 429 when that address is at the cap), or in total for the route the
// middleware is attached to with per_ip=false (503 when the route is at it).
//
// per_ip=false used to key the count on the request's Host, which the client
// writes, so every distinct Host got its own allowance and the cap the
// dashboard labelled "Max Concurrent Requests" held for nobody (ADR 0047).
func NewInflightReq(cfg map[string]string) (kind.Middleware, error) {
	amount, err := kind.ParseIntStrict(cfg["amount"], 0)
	if err != nil {
		return nil, kind.CfgError("amount", cfg["amount"], err)
	}
	if amount <= 0 {
		return nil, fmt.Errorf("inflightreq requires amount > 0")
	}
	perIP, err := kind.ParseBoolStrict(cfg["per_ip"], true)
	if err != nil {
		return nil, kind.CfgError("per_ip", cfg["per_ip"], err)
	}
	if !perIP {
		return MaxConnections(amount), nil
	}
	return MaxConnectionsPerIP(amount, PerIP), nil
}
