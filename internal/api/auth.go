package api

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) Login(_ context.Context, req *gateonv1.LoginRequest) (*gateonv1.LoginResponse, error) {
	if s.Auth == nil {
		return &gateonv1.LoginResponse{}, nil
	}
	token, user, err := s.Auth.Authenticate(req.Username, req.Password)
	if err != nil {
		return nil, err
	}
	return &gateonv1.LoginResponse{Token: token, User: user}, nil
}
