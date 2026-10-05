// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

// SQL queries for user management. Dialect.Rebind replaces ? with $N (Postgres) as needed.
const (
	QueryCountUsers           = "SELECT 1 FROM users LIMIT 1"
	QueryUserByUsername       = "SELECT id, username, password, role, failed_attempts, locked_until, two_factor_enabled, two_factor_secret, recovery_codes, disabled, two_factor_pending FROM users WHERE username = ?"
	QueryUserByID             = "SELECT id, username, password, role, failed_attempts, locked_until, two_factor_enabled, two_factor_secret, recovery_codes, disabled, two_factor_pending FROM users WHERE id = ?"
	QueryCountUsersSearch     = "SELECT COALESCE(COUNT(*), 0) FROM users WHERE username LIKE ?"
	QueryListUsersBase        = "SELECT id, username, role, two_factor_enabled, disabled, two_factor_pending FROM users WHERE username LIKE ? ORDER BY username ASC"
	QueryListUsersLimitOffset = " LIMIT ? OFFSET ?"

	QueryIncrementFailedAttempts = "UPDATE users SET failed_attempts = failed_attempts + 1, locked_until = ? WHERE username = ?"
	QueryResetFailedAttempts     = "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?"

	QueryUpdateUserDisabled     = "UPDATE users SET disabled = ? WHERE id = ?"
	QueryUpdateTwoFactorPending = "UPDATE users SET two_factor_pending = ? WHERE id = ?"

	// QueryInsertUser creates an account, and nothing else: a username another
	// account has is refused by the table's unique constraint. That refusal is
	// the check, so two creates racing for one name cannot both succeed.
	QueryInsertUser = "INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)"

	// QueryUpdateUser and QueryUpdateUserWithPassword edit the account an id
	// names. A rename onto a taken username is refused the same way.
	QueryUpdateUser = "UPDATE users SET username = ?, role = ? WHERE id = ?"
	// #nosec G101 -- a parameterised statement, not a credential. Every value
	// is bound.
	QueryUpdateUserWithPassword = "UPDATE users SET username = ?, password = ?, role = ? WHERE id = ?"

	// QuerySessionBindingByID reads only the columns that make up a session
	// binding (see revocation.go). Kept narrow so the per-verify cache miss is
	// as cheap as possible and so the password hash is never pulled into a
	// wider struct that might get logged or serialized.
	QuerySessionBindingByID = "SELECT password, role, disabled, session_epoch FROM users WHERE id = ?"

	// QueryAdvanceSessionEpoch is a sign-out: it moves the account to its next
	// epoch, which every session issued before it no longer matches.
	QueryAdvanceSessionEpoch = "UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?"

	// QueryLoginSources and QueryUpdateLoginSources read and write the source
	// prefixes an account has signed in from (ADR 0050).
	QueryLoginSources       = "SELECT login_sources FROM users WHERE id = ?"
	QueryUpdateLoginSources = "UPDATE users SET login_sources = ? WHERE id = ?"
	QueryUsernameByID       = "SELECT username FROM users WHERE id = ?"

	QueryDeleteUser = "DELETE FROM users WHERE id = ?"
	// #nosec G101 -- a parameterised statement, not a credential. Both values
	// are bound.
	QueryUpdatePassword = "UPDATE users SET password = ? WHERE id = ?"
	QueryUpdate2FA      = "UPDATE users SET two_factor_enabled = ?, two_factor_secret = ?, recovery_codes = ? WHERE id = ?"

	// QueryResetTwoFactor is an administrator's reset of another account's
	// second factor (ADR 0057), in one statement so no half of it can land
	// alone: the secret and recovery codes go, enrolment is required again at
	// the next sign-in, and every session ends.
	// #nosec G101 -- a parameterised statement, not a credential. Every value
	// is bound or a constant.
	QueryResetTwoFactor = "UPDATE users SET two_factor_enabled = ?, two_factor_secret = '', recovery_codes = '', " +
		"two_factor_pending = ?, session_epoch = session_epoch + 1 WHERE id = ?"

	// QueryTwoFactorSecrets and QueryUpdateTwoFactorSecret re-encrypt every
	// stored second factor when the session key is rotated.
	// #nosec G101 -- a query naming a column, not a credential.
	QueryTwoFactorSecrets = "SELECT id, two_factor_secret FROM users WHERE two_factor_secret <> ''"
	// #nosec G101 -- a parameterised statement, not a credential. Every value
	// is bound.
	QueryUpdateTwoFactorSecret = "UPDATE users SET two_factor_secret = ? WHERE id = ?"
)
