// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"github.com/gsoultan/gateon/pkg/proxy"
)

// RouteStatsProvider returns target stats for a route.
type RouteStatsProvider func(routeID string) []proxy.TargetStats
