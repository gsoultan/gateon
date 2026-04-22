package api

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) ListTLSOptions(ctx context.Context, _ *gateonv1.ListTLSOptionsRequest) (*gateonv1.ListTLSOptionsResponse, error) {
	if s.TLSOptions == nil {
		return &gateonv1.ListTLSOptionsResponse{TlsOptions: nil}, nil
	}
	return &gateonv1.ListTLSOptionsResponse{TlsOptions: s.TLSOptions.List(ctx)}, nil
}

func (s *ApiService) UpdateTLSOption(ctx context.Context, req *gateonv1.UpdateTLSOptionRequest) (*gateonv1.UpdateTLSOptionResponse, error) {
	if s.TLSOptions == nil || req == nil || req.TlsOption == nil {
		return &gateonv1.UpdateTLSOptionResponse{Success: false}, nil
	}
	if err := s.TLSOptions.Update(ctx, req.TlsOption); err != nil {
		return &gateonv1.UpdateTLSOptionResponse{Success: false}, err
	}
	return &gateonv1.UpdateTLSOptionResponse{Success: true}, nil
}

func (s *ApiService) DeleteTLSOption(ctx context.Context, req *gateonv1.DeleteTLSOptionRequest) (*gateonv1.DeleteTLSOptionResponse, error) {
	if s.TLSOptions == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteTLSOptionResponse{Success: false}, nil
	}
	if err := s.TLSOptions.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteTLSOptionResponse{Success: false}, err
	}
	return &gateonv1.DeleteTLSOptionResponse{Success: true}, nil
}
