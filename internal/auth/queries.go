package auth

// SQL queries for user management. Dialect.Rebind replaces ? with $N (Postgres) as needed.
const (
	QueryCountUsers           = "SELECT COUNT(*) FROM users"
	QueryUserByUsername       = "SELECT id, username, password, role, failed_attempts, locked_until FROM users WHERE username = ?"
	QueryCountUsersSearch     = "SELECT COUNT(*) FROM users WHERE username LIKE ?"
	QueryListUsersBase        = "SELECT id, username, role FROM users WHERE username LIKE ? ORDER BY username ASC"
	QueryListUsersLimitOffset = " LIMIT ? OFFSET ?"

	QueryIncrementFailedAttempts = "UPDATE users SET failed_attempts = failed_attempts + 1, locked_until = ? WHERE username = ?"
	QueryResetFailedAttempts     = "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?"

	QueryInsertUserSQLitePostgresWithPassword = `INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET username=excluded.username, password=excluded.password, role=excluded.role`
	QueryInsertUserSQLitePostgresNoPassword = `INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET username=excluded.username, role=excluded.role`

	QueryInsertUserMySQLWithPassword = `INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE username=VALUES(username), password=VALUES(password), role=VALUES(role)`
	QueryInsertUserMySQLNoPassword = `INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE username=VALUES(username), role=VALUES(role)`

	QueryDeleteUser     = "DELETE FROM users WHERE id = ?"
	QueryUpdatePassword = "UPDATE users SET password = ? WHERE id = ?"
)
