// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) ListRoutes(ctx context.Context, _ *gateonv1.ListRoutesRequest) (*gateonv1.ListRoutesResponse, error) {
	if s.Routes == nil {
		return &gateonv1.ListRoutesResponse{Routes: nil}, nil
	}
	return &gateonv1.ListRoutesResponse{Routes: s.Routes.List(ctx)}, nil
}

func (s *ApiService) UpdateRoute(ctx context.Context, req *gateonv1.UpdateRouteRequest) (*gateonv1.UpdateRouteResponse, error) {
	if s.Routes == nil || req == nil || req.Route == nil {
		return &gateonv1.UpdateRouteResponse{Success: false}, nil
	}
	// Through the domain service, as the REST handler: a route needs a service
	// and, unless it is L4, a rule, and is given an id if it arrived without
	// one. Written to the store directly, a route with no id was stored under
	// "" -- which neither transport will delete -- and one with no service was
	// matched and had no backend to reach. See domain_services.go.
	if err := s.routeService().SaveRoute(ctx, req.Route); err != nil {
		return &gateonv1.UpdateRouteResponse{Success: false}, err
	}
	s.logAudit(ctx, "update", "route", fmt.Sprintf("Updated route %s", req.Route.Id))
	return &gateonv1.UpdateRouteResponse{Success: true}, nil
}

func (s *ApiService) DeleteRoute(ctx context.Context, req *gateonv1.DeleteRouteRequest) (*gateonv1.DeleteRouteResponse, error) {
	if s.Routes == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteRouteResponse{Success: false}, nil
	}
	if err := s.routeService().DeleteRoute(ctx, req.Id); err != nil {
		return &gateonv1.DeleteRouteResponse{Success: false}, err
	}
	s.logAudit(ctx, "delete", "route", fmt.Sprintf("Deleted route %s", req.Id))
	return &gateonv1.DeleteRouteResponse{Success: true}, nil
}
