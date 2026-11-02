// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/gsoultan/gateon/internal/domain/route"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The bounds on a list request's paging, the REST handlers' too: page is what
// a caller turns into an enormous offset, page_size into one enormous answer.
const (
	MaxListPage     int32 = 1_000_000
	MaxListPageSize int32 = 1_000
)

// listPage clamps a requested page and page size to the bounds above. Zero
// page_size is every item, as over REST.
//
// The Connect and gRPC list calls ignored page, page_size and search, always
// answered with everything, and left total_count at zero -- so a client that
// paged, as the dashboard does over REST, was told there was nothing to page.
func listPage(page, size int32) (int32, int32) {
	return min(max(page, 0), MaxListPage), min(max(size, 0), MaxListPageSize)
}

func (s *ApiService) ListRoutes(ctx context.Context, req *gateonv1.ListRoutesRequest) (*gateonv1.ListRoutesResponse, error) {
	if s.Routes == nil {
		return &gateonv1.ListRoutesResponse{Routes: nil}, nil
	}
	page, size := listPage(req.GetPage(), req.GetPageSize())
	routes, total := s.Routes.ListPaginated(ctx, page, size, req.GetSearch(), nil)
	return &gateonv1.ListRoutesResponse{Routes: routes, TotalCount: total, Page: page, PageSize: size}, nil
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
		return &gateonv1.UpdateRouteResponse{Success: false}, mapRouteSaveError(err)
	}
	s.logAudit(ctx, "update", "route", fmt.Sprintf("Updated route %s", req.Route.Id))
	return &gateonv1.UpdateRouteResponse{Success: true}, nil
}

// mapRouteSaveError renders a rule the router cannot read (ADR 0043) as
// InvalidArgument, with the position and reason, where it used to surface as
// Unknown; a binding refusal maps as mapBindingRefusal says.
func mapRouteSaveError(err error) error {
	if errors.Is(err, route.ErrInvalidRule) || errors.Is(err, route.ErrInvalidStreamMode) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return mapBindingRefusal(err)
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
