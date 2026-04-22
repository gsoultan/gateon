package api

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) ListServices(ctx context.Context, _ *gateonv1.ListServicesRequest) (*gateonv1.ListServicesResponse, error) {
	if s.Services == nil {
		return &gateonv1.ListServicesResponse{Services: nil}, nil
	}
	return &gateonv1.ListServicesResponse{Services: s.Services.List(ctx)}, nil
}

func (s *ApiService) UpdateService(ctx context.Context, req *gateonv1.UpdateServiceRequest) (*gateonv1.UpdateServiceResponse, error) {
	if s.Services == nil || req == nil || req.Service == nil {
		return &gateonv1.UpdateServiceResponse{Success: false}, nil
	}
	if err := s.Services.Update(ctx, req.Service); err != nil {
		return &gateonv1.UpdateServiceResponse{Success: false}, err
	}
	return &gateonv1.UpdateServiceResponse{Success: true}, nil
}

func (s *ApiService) DeleteService(ctx context.Context, req *gateonv1.DeleteServiceRequest) (*gateonv1.DeleteServiceResponse, error) {
	if s.Services == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteServiceResponse{Success: false}, nil
	}
	if err := s.Services.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteServiceResponse{Success: false}, err
	}
	return &gateonv1.DeleteServiceResponse{Success: true}, nil
}
