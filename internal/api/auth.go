package api

import (
	"context"
	"errors"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) Login(_ context.Context, req *gateonv1.LoginRequest) (*gateonv1.LoginResponse, error) {
	if s.Auth == nil {
		return &gateonv1.LoginResponse{}, nil
	}
	token, user, err := s.Auth.Authenticate(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrTwoFactorRequired) {
			return &gateonv1.LoginResponse{
				User:              user,
				TwoFactorRequired: true,
			}, nil
		}
		// Administrator mandated 2FA but the user hasn't enrolled: signal the client
		// to run first-time enrollment. No token/cookie is issued yet.
		if errors.Is(err, auth.ErrTwoFactorSetupRequired) {
			return &gateonv1.LoginResponse{
				User:                   user,
				TwoFactorSetupRequired: true,
			}, nil
		}
		return nil, err
	}
	return &gateonv1.LoginResponse{Token: token, User: user}, nil
}

func (s *ApiService) Setup2FA(_ context.Context, req *gateonv1.Setup2FARequest) (*gateonv1.Setup2FAResponse, error) {
	if s.Auth == nil {
		return nil, errors.New("auth service not initialized")
	}
	secret, qr, recovery, err := s.Auth.Setup2FA(req.Id)
	if err != nil {
		return nil, err
	}
	return &gateonv1.Setup2FAResponse{
		Secret:        secret,
		QrCodeUrl:     qr,
		RecoveryCodes: recovery,
	}, nil
}

func (s *ApiService) Verify2FA(_ context.Context, req *gateonv1.Verify2FARequest) (*gateonv1.Verify2FAResponse, error) {
	if s.Auth == nil {
		return nil, errors.New("auth service not initialized")
	}
	success, token, user, err := s.Auth.Verify2FA(req.Id, req.Code)
	if err != nil {
		return nil, err
	}
	return &gateonv1.Verify2FAResponse{
		Success: success,
		Token:   token,
		User:    user,
	}, nil
}
