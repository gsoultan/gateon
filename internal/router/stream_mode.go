// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/deadline"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// streamModeMiddleware tells the listener's stream decision what the route's
// stream_mode says (ADR 0064), or is nil for a route that leaves it to the
// response (auto), so such a route's chain is what it was. An unknown value
// -- a newer client, a hand-edited store -- is auto, the behaviour every route
// had before the field existed.
func streamModeMiddleware(rt *gateonv1.Route) middleware.Middleware {
	mode, ok := routeStreamMode(rt.GetStreamMode())
	if !ok {
		return nil
	}
	if mode == request.StreamAlways {
		if l := deadline.CurrentStreamLimits(); l.Idle <= 0 && l.MaxLifetime <= 0 {
			logger.L.LogWarn("route streams always, but both stream bounds are disabled; "+
				"its responses keep the entrypoint's timeouts instead of having none",
				"route", RouteLabel(rt), "idle_env", deadline.IdleTimeoutEnv, "lifetime_env", deadline.MaxLifetimeEnv)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rs := request.GetRequestState(r); rs != nil && rs.Stream != nil {
				rs.Stream.SetStreamMode(mode)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// routeStreamMode maps a route's stream_mode onto the listener's, reporting
// false for auto and for any value it does not know.
func routeStreamMode(m gateonv1.Route_StreamMode) (request.StreamMode, bool) {
	switch m {
	case gateonv1.Route_STREAM_MODE_ALWAYS:
		return request.StreamAlways, true
	case gateonv1.Route_STREAM_MODE_NEVER:
		return request.StreamNever, true
	default:
		return request.StreamAuto, false
	}
}
