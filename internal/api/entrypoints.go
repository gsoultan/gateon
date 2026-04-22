package api

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) ListEntryPoints(ctx context.Context, _ *gateonv1.ListEntryPointsRequest) (*gateonv1.ListEntryPointsResponse, error) {
	if s.EntryPoints == nil {
		return &gateonv1.ListEntryPointsResponse{EntryPoints: nil}, nil
	}
	return &gateonv1.ListEntryPointsResponse{EntryPoints: s.EntryPoints.List(ctx)}, nil
}

func (s *ApiService) UpdateEntryPoint(ctx context.Context, req *gateonv1.UpdateEntryPointRequest) (*gateonv1.UpdateEntryPointResponse, error) {
	if s.EntryPoints == nil || req == nil || req.EntryPoint == nil {
		return &gateonv1.UpdateEntryPointResponse{Success: false}, nil
	}
	if err := s.EntryPoints.Update(ctx, req.EntryPoint); err != nil {
		return &gateonv1.UpdateEntryPointResponse{Success: false}, err
	}
	return &gateonv1.UpdateEntryPointResponse{Success: true}, nil
}

func (s *ApiService) DeleteEntryPoint(ctx context.Context, req *gateonv1.DeleteEntryPointRequest) (*gateonv1.DeleteEntryPointResponse, error) {
	if s.EntryPoints == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteEntryPointResponse{Success: false}, nil
	}
	if err := s.EntryPoints.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteEntryPointResponse{Success: false}, err
	}
	return &gateonv1.DeleteEntryPointResponse{Success: true}, nil
}
