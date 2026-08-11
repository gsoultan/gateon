// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Invalidator notifies observers when route proxies must be invalidated.
type Invalidator interface {
	InvalidateRoute(id string)
	InvalidateRoutes(strategy func(*gateonv1.Route) bool)
	InvalidateTLS()
	InvalidateWAF()
}
