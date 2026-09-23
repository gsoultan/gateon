// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"fmt"
	"net/http"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

func NewInflightReq(cfg map[string]string) (kind.Middleware, error) {
	amount, err := kind.ParseIntStrict(cfg["amount"], 0)
	if err != nil {
		return nil, kind.CfgError("amount", cfg["amount"], err)
	}
	if amount <= 0 {
		return nil, fmt.Errorf("inflightreq requires amount > 0")
	}
	perIP := kind.ParseBoolStrict(cfg["per_ip"], true)
	keyFunc := PerIP
	if !perIP {
		keyFunc = func(r *http.Request) string { return r.Host }
	}
	return MaxConnectionsPerIP(amount, keyFunc), nil
}
