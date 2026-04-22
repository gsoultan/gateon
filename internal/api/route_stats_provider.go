package api

import (
	"github.com/gsoultan/gateon/pkg/proxy"
)

// RouteStatsProvider returns target stats for a route.
type RouteStatsProvider func(routeID string) []proxy.TargetStats
