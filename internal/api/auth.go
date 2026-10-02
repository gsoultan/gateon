// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/metadata"
)

func (s *ApiService) Login(ctx context.Context, req *gateonv1.LoginRequest) (*gateonv1.LoginResponse, error) {
	if !auth.Available(s.Auth) {
		return &gateonv1.LoginResponse{}, nil
	}
	token, user, err := s.Auth.Authenticate(req.Username, req.Password)
	if err != nil {
		// The password was right and a second factor is owed. No session: the
		// answer carries the challenge the second step requires, which is not
		// one (see auth.Manager.Verify2FA and ADR 0039).
		if errors.Is(err, auth.ErrTwoFactorRequired) {
			return &gateonv1.LoginResponse{
				User:               user,
				TwoFactorRequired:  true,
				TwoFactorChallenge: auth.ChallengeFrom(err),
			}, nil
		}
		// Administrator mandated 2FA but the user hasn't enrolled: signal the client
		// to run first-time enrollment. No token/cookie is issued yet.
		if errors.Is(err, auth.ErrTwoFactorSetupRequired) {
			return &gateonv1.LoginResponse{
				User:                   user,
				TwoFactorSetupRequired: true,
				TwoFactorChallenge:     auth.ChallengeFrom(err),
			}, nil
		}
		s.logAudit(ctx, "login_failed", "auth", fmt.Sprintf("Failed login attempt for user: %s", req.Username))
		return nil, err
	}
	s.logAudit(ctx, "login_success", "auth", fmt.Sprintf("User logged in: %s", req.Username))
	if calledFromBrowser(ctx) {
		token = ""
	}
	return &gateonv1.LoginResponse{Token: token, User: user}, nil
}

// calledFromBrowser reports whether the gRPC call in ctx was sent by a browser.
//
// POST /v1/login gives a browser the session only as its HttpOnly cookie: a
// token in the body is a string any script in the page can read and carry off
// as a bearer credential. The Login RPC sets no cookie and put the token in its
// reply for every caller, and a browser can make that call -- script on the
// dashboard's origin sending application/grpc over HTTP/2. The management
// server serves gRPC through grpc-go's ServeHTTP transport, which copies every
// request header into the call's metadata, and every browser sends
// Sec-Fetch-Mode on every request, where page script can neither set nor
// remove it (see handlers.sentByBrowser). So a browser gets a successful
// sign-in with no token in it, and uses /v1/login for a session; a native gRPC
// client never sends the header and keeps its token.
//
// REST calls Login with an HTTP request's context, which carries no gRPC
// metadata: /v1/login needs the token to set the cookie, and withholds it from
// the body itself. gRPC-Web does not reach Login at all -- the management
// server passes it to grpc-go unconverted, and grpc-go refuses the content type
// before any RPC runs -- and would carry the header the same way if it did.
func calledFromBrowser(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	return ok && len(md.Get("sec-fetch-mode")) > 0
}

func (s *ApiService) Setup2FA(ctx context.Context, req *gateonv1.Setup2FARequest) (*gateonv1.Setup2FAResponse, error) {
	if !auth.Available(s.Auth) {
		return nil, errors.New("auth service not initialized")
	}
	enrolment, err := s.Auth.Setup2FA(req.Id, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, auth.ErrAccountLocked) {
			s.logAudit(ctx, "setup_2fa_refused", "user",
				fmt.Sprintf("2FA setup refused for user %s: %v", req.Id, err))
		}
		return nil, err
	}
	s.logAudit(ctx, "setup_2fa", "user", fmt.Sprintf("User initiated 2FA setup: %s", req.Id))
	return &gateonv1.Setup2FAResponse{
		Secret:        enrolment.Secret,
		QrCodeUrl:     enrolment.QRCodeURL,
		RecoveryCodes: enrolment.RecoveryCodes,
		Challenge:     enrolment.Challenge,
	}, nil
}

func (s *ApiService) Verify2FA(ctx context.Context, req *gateonv1.Verify2FARequest) (*gateonv1.Verify2FAResponse, error) {
	if !auth.Available(s.Auth) {
		return nil, errors.New("auth service not initialized")
	}
	// The challenge goes to the service, which checks it before the code, for
	// every caller and every transport: this is the only way in to a session
	// for a 2FA account, and the decision does not depend on who is asking.
	success, token, user, err := s.Auth.Verify2FA(req.Challenge, req.Id, req.Code)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidChallenge) {
			// Not a guess at the code, and not logged as one.
			s.logAudit(ctx, "verify_2fa_refused", "user",
				fmt.Sprintf("2FA step without a valid sign-in challenge for user: %s", req.Id))
			return nil, err
		}
		s.logAudit(ctx, "verify_2fa_failed", "user", fmt.Sprintf("Failed 2FA verification for user: %s", req.Id))
		return nil, err
	}
	if success {
		s.logAudit(ctx, "verify_2fa_success", "user", fmt.Sprintf("Successful 2FA verification for user: %s", req.Id))
	} else {
		s.logAudit(ctx, "verify_2fa_failed", "user", fmt.Sprintf("Invalid 2FA code for user: %s", req.Id))
	}
	return &gateonv1.Verify2FAResponse{
		Success: success,
		Token:   token,
		User:    user,
	}, nil
}
