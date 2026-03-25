package domain

import (
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ProxyInvalidator notifies observers when route proxies must be invalidated.
// Domain services emit invalidation events; server (or other observers) subscribe and invalidate.
// Decouples domain from infrastructure (Observer pattern).
type ProxyInvalidator interface {
	// InvalidateRoute invalidates the proxy cache for the given route ID.
	InvalidateRoute(id string)
	// InvalidateRoutes invalidates proxies for all routes matching the strategy.
	InvalidateRoutes(strategy func(*gateonv1.Route) bool)
}
