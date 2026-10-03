// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"github.com/gsoultan/gateon/internal/auth/apitoken"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Service defines the contract for authentication and user management.
// It is implemented by Manager.
type Service interface {
	IsSetupDone() bool
	// Authenticate checks a password sign-in from source, the caller's address,
	// under the lockout of ADR 0050: failures are counted per account and source
	// prefix, and per account, and neither locks the owner out from a source the
	// account has signed in from before.
	Authenticate(username, password, source string) (string, *gateonv1.User, error)
	// APITokens is the scrape-credential store (ADR 0050), or nil when there is
	// no database yet.
	APITokens() *apitoken.Store
	VerifyToken(token string) (any, error)
	ListUsers(page, pageSize int32, search string) ([]*gateonv1.User, int32, error)
	UpsertUser(u *gateonv1.User) error
	DeleteUser(id string) error
	ChangePassword(id, password string) error
	// ChangeOwnPassword is ChangePassword for the account's own user, who must
	// present the current password; a wrong one counts towards login's lockout.
	ChangeOwnPassword(id, current, password string) error
	// UpdateSymmetricKey puts a new session key in force at once: every
	// session ends, and every stored second factor is re-encrypted under it.
	// See Manager.UpdateSymmetricKey.
	UpdateSymmetricKey(key string) error
	SetUserDisabled(id string, disabled bool) error
	SetTwoFactorPending(id string, pending bool) error

	// EndSessions ends every live session of account id: a sign-out, which
	// signs the account out everywhere. See Manager.EndSessions.
	EndSessions(id string) error

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

	// Setup2FA begins self-service TOTP enrolment for account id. It requires
	// the account's current password and applies login's lockout to it, so a
	// session alone -- which script in the dashboard can ride without reading
	// -- is not enough to put the second factor in someone else's hands.
	//
	// The Enrolment carries the challenge Verify2FA requires to finish it.
	Setup2FA(id, password string) (Enrolment, error)
	EnrollPending2FA(username, password, source string) (string, string, []string, string, error)
	// Verify2FA checks a code for account id, given the challenge that proves
	// the password step -- from Authenticate's SecondStepError or Setup2FA --
	// and issues a session. See ADR 0039.
	Verify2FA(challenge, id, code string) (bool, string, *gateonv1.User, error)
	Disable2FA(id string) error

	Close() error
}
