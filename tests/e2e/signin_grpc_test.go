// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"errors"
	"sync"

	"github.com/gsoultan/gateon/internal/auth/authtest"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// grpcSecrets is the authenticator grpcSignIn enrolled each account with, by
// account id, so a later sign-in of the same account answers its code.
var grpcSecrets sync.Map

// grpcSignIn signs username in over gRPC the way a native client must now that
// every account has a second factor (ADR 0088): Login answers a challenge and
// no session, Enroll2FA the first time, and Verify2FA's reply carries the
// session token.
func grpcSignIn(ctx context.Context, client gateonv1.ApiServiceClient, username, password string) (string, error) {
	login, err := client.Login(ctx, &gateonv1.LoginRequest{Username: username, Password: password})
	if err != nil {
		return "", err
	}
	id := login.GetUser().GetId()
	if login.GetTwoFactorSetupRequired() {
		enrol, err := client.Enroll2FA(ctx, &gateonv1.Enroll2FARequest{Username: username, Password: password})
		if err != nil {
			return "", err
		}
		id = enrol.GetId()
		grpcSecrets.Store(id, enrol.GetSecret())
	}
	s, ok := grpcSecrets.Load(id)
	if !ok {
		return "", errors.New("no authenticator enrolled for " + username)
	}
	secret, _ := s.(string)
	code, err := authtest.Code(secret)
	if err != nil {
		return "", err
	}
	verified, err := client.Verify2FA(ctx, &gateonv1.Verify2FARequest{Id: id, Code: code, Challenge: login.GetTwoFactorChallenge()})
	if err != nil {
		return "", err
	}
	return verified.GetToken(), nil
}
