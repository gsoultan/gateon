package api

import (
	"context"

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
	if err := s.Routes.Update(ctx, req.Route); err != nil {
		return &gateonv1.UpdateRouteResponse{Success: false}, err
	}
	return &gateonv1.UpdateRouteResponse{Success: true}, nil
}

func (s *ApiService) DeleteRoute(ctx context.Context, req *gateonv1.DeleteRouteRequest) (*gateonv1.DeleteRouteResponse, error) {
	if s.Routes == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteRouteResponse{Success: false}, nil
	}
	if err := s.Routes.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteRouteResponse{Success: false}, err
	}
	return &gateonv1.DeleteRouteResponse{Success: true}, nil
}
