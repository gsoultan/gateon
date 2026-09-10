// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Service defines the contract for authentication and user management.
// It is implemented by Manager.
type Service interface {
	IsSetupDone() bool
	Authenticate(username, password string) (string, *gateonv1.User, error)
	VerifyToken(token string) (any, error)
	ListUsers(page, pageSize int32, search string) ([]*gateonv1.User, int32, error)
	UpsertUser(u *gateonv1.User) error
	DeleteUser(id string) error
	ChangePassword(id, password string) error
	UpdateSymmetricKey(key string)
	SetUserDisabled(id string, disabled bool) error
	SetTwoFactorPending(id string, pending bool) error

	// InvalidateBinding drops a cached session binding without republishing it.
	// It is how an invalidation from another instance is applied; see ADR 0012
	// for why the remote path may only invalidate and never populate.
	InvalidateBinding(id string)

	// SetBindingPublisher installs the peer-notification publisher. It is on
	// the interface so a Holder can re-apply it to the Manager that Setup
	// creates on a first run, which does not exist when the publisher is
	// configured at startup.
	SetBindingPublisher(p BindingPublisher)

	// 2FA methods
	Setup2FA(id string) (string, string, []string, error)
	EnrollPending2FA(username, password string) (string, string, []string, string, error)
	Verify2FA(id, code string) (bool, string, *gateonv1.User, error)
	Disable2FA(id string) error

	Close() error
}
