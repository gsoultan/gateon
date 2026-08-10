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

	QueryInsertUserSQLitePostgresWithPassword = `INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET password=excluded.password, role=excluded.role`
	QueryInsertUserSQLitePostgresNoPassword = `INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET role=excluded.role`

	QueryInsertUserMySQLWithPassword = `INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE password=VALUES(password), role=VALUES(role)`
	QueryInsertUserMySQLNoPassword = `INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE role=VALUES(role)`

	// QuerySessionBindingByID reads only the columns that make up a session
	// binding (see revocation.go). Kept narrow so the per-verify cache miss is
	// as cheap as possible and so the password hash is never pulled into a
	// wider struct that might get logged or serialized.
	QuerySessionBindingByID = "SELECT password, role, disabled FROM users WHERE id = ?"

	QueryDeleteUser     = "DELETE FROM users WHERE id = ?"
	QueryUpdatePassword = "UPDATE users SET password = ? WHERE id = ?"
	QueryUpdate2FA      = "UPDATE users SET two_factor_enabled = ?, two_factor_secret = ?, recovery_codes = ? WHERE id = ?"
)
