package api

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) ListMiddlewares(ctx context.Context, _ *gateonv1.ListMiddlewaresRequest) (*gateonv1.ListMiddlewaresResponse, error) {
	if s.Middlewares == nil {
		return &gateonv1.ListMiddlewaresResponse{Middlewares: nil}, nil
	}
	return &gateonv1.ListMiddlewaresResponse{Middlewares: s.Middlewares.List(ctx)}, nil
}

func (s *ApiService) UpdateMiddleware(ctx context.Context, req *gateonv1.UpdateMiddlewareRequest) (*gateonv1.UpdateMiddlewareResponse, error) {
	if s.Middlewares == nil || req == nil || req.Middleware == nil {
		return &gateonv1.UpdateMiddlewareResponse{Success: false}, nil
	}
	if err := s.Middlewares.Update(ctx, req.Middleware); err != nil {
		return &gateonv1.UpdateMiddlewareResponse{Success: false}, err
	}
	return &gateonv1.UpdateMiddlewareResponse{Success: true}, nil
}

func (s *ApiService) DeleteMiddleware(ctx context.Context, req *gateonv1.DeleteMiddlewareRequest) (*gateonv1.DeleteMiddlewareResponse, error) {
	if s.Middlewares == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteMiddlewareResponse{Success: false}, nil
	}
	if err := s.Middlewares.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteMiddlewareResponse{Success: false}, err
	}
	return &gateonv1.DeleteMiddlewareResponse{Success: true}, nil
}
