package auth

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

type Manager struct {
	db           *sql.DB
	dialect      db.Dialect
	symmetricKey paseto.V4SymmetricKey
	encKey       []byte
	logger       logger.Logger
}

// NewManager creates an auth manager using the given database URL.
func NewManager(databaseURL, symmetricKey string, l logger.Logger) (*Manager, error) {
	database, dialect, err := db.Open(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Migrate(database, dialect); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	// PASETO v4 local keys must be 32 bytes
	keyBytes := []byte(symmetricKey)
	if len(keyBytes) < 32 {
		// Pad or return error
		return nil, fmt.Errorf("PASETO v4 symmetric key must be at least 32 bytes")
	}
	key, err := paseto.V4SymmetricKeyFromBytes(keyBytes[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create PASETO v4 key: %w", err)
	}

	m := &Manager{
		db:           database,
		dialect:      dialect,
		symmetricKey: key,
		encKey:       append([]byte(nil), keyBytes[:32]...),
		logger:       l,
	}

	return m, nil
}

func (m *Manager) IsSetupDone() bool {
	var count int
	q := m.dialect.Rebind(QueryCountUsers)
	err := m.db.QueryRow(q).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

func (m *Manager) Authenticate(username, password string) (string, *gateonv1.User, error) {
	var user gateonv1.User
	var hashed string
	var failedAttempts int
	var lockedUntil sql.NullTime
	var recoveryCodes string

	q := m.dialect.Rebind(QueryUserByUsername)
	err := m.db.QueryRow(q, username).
		Scan(&user.Id, &user.Username, &hashed, &user.Role, &failedAttempts, &lockedUntil,
			&user.TwoFactorEnabled, &user.TwoFactorSecret, &recoveryCodes,
			&user.Disabled, &user.TwoFactorPending)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil, ErrInvalidCredentials
		}
		return "", nil, err
	}

	if lockedUntil.Valid && time.Now().Before(lockedUntil.Time) {
		return "", nil, ErrAccountLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)); err != nil {
		m.handleFailedLogin(username, failedAttempts)
		return "", nil, ErrInvalidCredentials
	}

	// A disabled account is blocked AFTER a correct password (so an attacker can't
	// use this to enumerate which accounts are disabled vs. wrong-password).
	if user.Disabled {
		return "", nil, ErrAccountDisabled
	}

	m.resetFailedAttempts(username)

	if user.TwoFactorEnabled {
		// Never leak the secret or recovery codes on the 2FA challenge response.
		sanitizeUser(&user)
		return "", &user, ErrTwoFactorRequired
	}

	// An administrator mandated 2FA but the user has not enrolled yet: do not issue
	// a session. The client must run first-time TOTP enrollment (self-service
	// Setup2FA + Verify2FA) before login completes. The user id is returned (no
	// secret) so the client knows which account to enroll.
	if user.TwoFactorPending {
		sanitizeUser(&user)
		return "", &user, ErrTwoFactorSetupRequired
	}

	return m.issueToken(&user)
}

func (m *Manager) issueToken(user *gateonv1.User) (string, *gateonv1.User, error) {
	token := paseto.NewToken()
	now := time.Now()
	exp := now.Add(24 * time.Hour)

	token.SetExpiration(exp)
	token.SetIssuedAt(now)
	token.SetNotBefore(now)
	token.SetSubject(user.Id)
	token.SetString("id", user.Id)
	token.SetString("username", user.Username)
	token.SetString("role", user.Role)

	encrypted := token.V4Encrypt(m.symmetricKey, nil)

	sanitizeUser(user)
	return encrypted, user, nil
}

// sanitizeUser strips all credential-equivalent fields from a User before it is
// returned to a client to prevent leaking secrets over the wire.
func sanitizeUser(user *gateonv1.User) {
	if user == nil {
		return
	}
	user.Password = ""
	user.TwoFactorSecret = ""
	user.RecoveryCodes = nil
}

func (m *Manager) VerifyToken(token string) (any, error) {
	parser := paseto.NewParser()
	parsedToken, err := parser.ParseV4Local(m.symmetricKey, token, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims := &Claims{}
	if val, err := parsedToken.GetString("id"); err == nil {
		claims.ID = val
	}
	if val, err := parsedToken.GetString("username"); err == nil {
		claims.Username = val
	}
	if val, err := parsedToken.GetString("role"); err == nil {
		claims.Role = val
	}
	if val, err := parsedToken.GetExpiration(); err == nil {
		claims.Expiration = val
	}
	if val, err := parsedToken.GetIssuedAt(); err == nil {
		claims.IssuedAt = val
	}
	if val, err := parsedToken.GetNotBefore(); err == nil {
		claims.NotBefore = val
	}
	if val, err := parsedToken.GetSubject(); err == nil {
		claims.Subject = val
	}

	if err := claims.Validate(); err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return claims, nil
}

func (m *Manager) ListUsers(page, pageSize int32, search string) ([]*gateonv1.User, int32, error) {
	searchArg := "%" + search + "%"
	qCount := m.dialect.Rebind(QueryCountUsersSearch)
	var totalCount int
	err := m.db.QueryRow(qCount, searchArg).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	query := QueryListUsersBase
	var args []any
	args = append(args, searchArg)
	if pageSize > 0 {
		query += QueryListUsersLimitOffset
		args = append(args, pageSize, page*pageSize)
	}
	query = m.dialect.Rebind(query)

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*gateonv1.User
	for rows.Next() {
		var u gateonv1.User
		if err := rows.Scan(&u.Id, &u.Username, &u.Role, &u.TwoFactorEnabled, &u.Disabled, &u.TwoFactorPending); err != nil {
			return nil, 0, err
		}
		users = append(users, &u)
	}
	return users, int32(totalCount), nil
}

func (m *Manager) UpsertUser(u *gateonv1.User) error {
	if u.Id == "" {
		u.Id = uuid.New().String()
	}

	if u.Password != "" {
		hashed, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		return m.upsertUserWithPassword(u.Id, u.Username, string(hashed), u.Role)
	}
	return m.upsertUserWithPassword(u.Id, u.Username, "", u.Role)
}

func (m *Manager) upsertUserWithPassword(id, username, password, role string) error {
	if m.dialect.Driver == db.DriverMySQL {
		return m.upsertMySQL(id, username, password, role)
	}
	return m.upsertSQLitePostgres(id, username, password, role)
}

func (m *Manager) upsertSQLitePostgres(id, username, password, role string) error {
	if password != "" {
		q := m.dialect.Rebind(QueryInsertUserSQLitePostgresWithPassword)
		_, err := m.db.Exec(q, id, username, password, role)
		if err != nil {
			return fmt.Errorf("failed to upsert user with password (sqlite/postgres): %w", err)
		}
		return nil
	}
	q := m.dialect.Rebind(QueryInsertUserSQLitePostgresNoPassword)
	_, err := m.db.Exec(q, id, username, "", role)
	if err != nil {
		return fmt.Errorf("failed to upsert user without password (sqlite/postgres): %w", err)
	}
	return nil
}

func (m *Manager) upsertMySQL(id, username, password, role string) error {
	if password != "" {
		_, err := m.db.Exec(QueryInsertUserMySQLWithPassword, id, username, password, role)
		return err
	}
	_, err := m.db.Exec(QueryInsertUserMySQLNoPassword, id, username, "", role)
	return err
}

func (m *Manager) ChangePassword(id, password string) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	q := m.dialect.Rebind(QueryUpdatePassword)
	_, err = m.db.Exec(q, string(hashed), id)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	return nil
}

func (m *Manager) DeleteUser(id string) error {
	q := m.dialect.Rebind(QueryDeleteUser)
	_, err := m.db.Exec(q, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

func (m *Manager) UpdateSymmetricKey(key string) {
	keyBytes := []byte(key)
	if len(keyBytes) < 32 {
		return
	}
	k, err := paseto.V4SymmetricKeyFromBytes(keyBytes[:32])
	if err == nil {
		m.symmetricKey = k
		m.encKey = append([]byte(nil), keyBytes[:32]...)
	}
}

// EnrollPending2FA begins first-time TOTP enrollment for a user whom an
// administrator has flagged as 2FA-pending, during the login flow (before a
// session exists). It re-verifies the password so the TOTP secret and recovery
// codes are only ever disclosed to someone who already proved the first factor,
// and only when the account is genuinely pending (not already enrolled). It
// returns the same (secret, qrDataURL, recoveryCodes) tuple as Setup2FA plus the
// resolved user id so the caller can complete verification.
func (m *Manager) EnrollPending2FA(username, password string) (string, string, []string, string, error) {
	var id, hashed, role, recoveryCodes string
	var twoFactorEnabled, twoFactorPending, disabled bool
	var failedAttempts int
	var lockedUntil sql.NullTime
	var twoFactorSecret, uname string

	q := m.dialect.Rebind(QueryUserByUsername)
	err := m.db.QueryRow(q, username).Scan(&id, &uname, &hashed, &role, &failedAttempts, &lockedUntil,
		&twoFactorEnabled, &twoFactorSecret, &recoveryCodes, &disabled, &twoFactorPending)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", nil, "", ErrInvalidCredentials
		}
		return "", "", nil, "", err
	}

	if lockedUntil.Valid && time.Now().Before(lockedUntil.Time) {
		return "", "", nil, "", ErrAccountLocked
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)); err != nil {
		m.handleFailedLogin(username, failedAttempts)
		return "", "", nil, "", ErrInvalidCredentials
	}
	if disabled {
		return "", "", nil, "", ErrAccountDisabled
	}
	// Enrollment via this unauthenticated path is only for accounts an admin
	// mandated 2FA for and that haven't enrolled. Anything else must go through the
	// authenticated self-service Setup2FA endpoint.
	if twoFactorEnabled || !twoFactorPending {
		return "", "", nil, "", ErrInvalidCredentials
	}

	secret, qr, codes, err := m.Setup2FA(id)
	if err != nil {
		return "", "", nil, "", err
	}
	return secret, qr, codes, id, nil
}

func (m *Manager) Setup2FA(id string) (string, string, []string, error) {
	var user gateonv1.User
	var hashed, role, recoveryCodes string
	var failedAttempts int
	var lockedUntil sql.NullTime

	q := m.dialect.Rebind(QueryUserByID)
	err := m.db.QueryRow(q, id).Scan(&user.Id, &user.Username, &hashed, &role, &failedAttempts, &lockedUntil,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &recoveryCodes, &user.Disabled, &user.TwoFactorPending)
	if err != nil {
		return "", "", nil, err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Gateon",
		AccountName: user.Username,
	})
	if err != nil {
		return "", "", nil, err
	}

	// Generate cryptographically strong recovery codes; store only their hashes.
	plainCodes, hashedCodes, err := generateRecoveryCodes()
	if err != nil {
		return "", "", nil, err
	}

	// Encrypt the TOTP secret at rest.
	encSecret, err := encryptSecret(m.encKey, key.Secret())
	if err != nil {
		return "", "", nil, err
	}

	// Update user with secret but don't enable it yet.
	qUpdate := m.dialect.Rebind(QueryUpdate2FA)
	_, err = m.db.Exec(qUpdate, false, encSecret, strings.Join(hashedCodes, ","), id)
	if err != nil {
		return "", "", nil, err
	}

	var png []byte
	png, err = qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return "", "", nil, err
	}

	qrBase64 := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	return key.Secret(), qrBase64, plainCodes, nil
}

func (m *Manager) Verify2FA(id, code string) (bool, string, *gateonv1.User, error) {
	var user gateonv1.User
	var hashed, role, recoveryCodes string
	var failedAttempts int
	var lockedUntil sql.NullTime

	q := m.dialect.Rebind(QueryUserByID)
	err := m.db.QueryRow(q, id).Scan(&user.Id, &user.Username, &hashed, &role, &failedAttempts, &lockedUntil,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &recoveryCodes, &user.Disabled, &user.TwoFactorPending)
	if err != nil {
		return false, "", nil, err
	}

	// Enforce the same lockout used for password login to throttle brute-force
	// attempts against the 6-digit TOTP and recovery codes.
	if lockedUntil.Valid && time.Now().Before(lockedUntil.Time) {
		return false, "", nil, ErrAccountLocked
	}

	// The stored secret is encrypted at rest; keep the stored form for persistence
	// and decrypt a copy for validation.
	storedSecret := user.TwoFactorSecret
	plainSecret, err := decryptSecret(m.encKey, storedSecret)
	if err != nil {
		return false, "", nil, err
	}

	// Recovery codes are only valid once 2FA is fully enabled, never during the
	// enrollment verification step.
	if user.TwoFactorEnabled && recoveryCodes != "" {
		hashes := strings.Split(recoveryCodes, ",")
		if i := matchRecoveryCode(hashes, code); i >= 0 {
			newCodes := removeAt(hashes, i)
			qUpdate := m.dialect.Rebind(QueryUpdate2FA)
			if _, err = m.db.Exec(qUpdate, true, storedSecret, strings.Join(newCodes, ","), id); err != nil {
				return false, "", nil, err
			}
			m.resetFailedAttempts(user.Username)
			token, u, err := m.issueToken(&user)
			return true, token, u, err
		}
	}

	if totp.Validate(code, plainSecret) {
		if !user.TwoFactorEnabled {
			// Enable 2FA on first successful verification.
			qUpdate := m.dialect.Rebind(QueryUpdate2FA)
			if _, err = m.db.Exec(qUpdate, true, storedSecret, recoveryCodes, id); err != nil {
				return false, "", nil, err
			}
			// Enrollment is complete; clear any admin-mandated pending flag so the
			// next login goes straight to the normal 2FA code challenge.
			if user.TwoFactorPending {
				if err = m.setTwoFactorPending(id, false); err != nil {
					return false, "", nil, err
				}
			}
		}
		m.resetFailedAttempts(user.Username)
		token, u, err := m.issueToken(&user)
		return true, token, u, err
	}

	// Invalid code: count it towards the lockout threshold.
	m.handleFailedLogin(user.Username, failedAttempts)
	return false, "", nil, ErrInvalidTwoFactorCode
}

func (m *Manager) Disable2FA(id string) error {
	qUpdate := m.dialect.Rebind(QueryUpdate2FA)
	_, err := m.db.Exec(qUpdate, false, "", "", id)
	return err
}

// SetUserDisabled enables or disables an account without deleting it. A disabled
// account is rejected at login (after a correct password) until re-enabled.
func (m *Manager) SetUserDisabled(id string, disabled bool) error {
	q := m.dialect.Rebind(QueryUpdateUserDisabled)
	if _, err := m.db.Exec(q, disabled, id); err != nil {
		return fmt.Errorf("failed to update disabled state: %w", err)
	}
	return nil
}

// SetTwoFactorPending marks (or clears) an administrator-mandated 2FA requirement.
// When set, the user is forced through first-time TOTP enrollment on next login.
// This never generates or exposes a TOTP secret — enrollment stays self-service so
// an admin can require 2FA without ever holding the user's second factor.
func (m *Manager) SetTwoFactorPending(id string, pending bool) error {
	return m.setTwoFactorPending(id, pending)
}

func (m *Manager) setTwoFactorPending(id string, pending bool) error {
	q := m.dialect.Rebind(QueryUpdateTwoFactorPending)
	if _, err := m.db.Exec(q, pending, id); err != nil {
		return fmt.Errorf("failed to update 2FA pending state: %w", err)
	}
	return nil
}

func (m *Manager) handleFailedLogin(username string, currentAttempts int) {
	var lockedUntil any
	if currentAttempts+1 >= MaxFailedAttempts {
		lockedUntil = time.Now().Add(LockoutDuration)
	}
	q := m.dialect.Rebind(QueryIncrementFailedAttempts)
	if _, err := m.db.Exec(q, lockedUntil, username); err != nil {
		m.logger.LogError("failed to increment failed login attempts", "error", err, "username", username)
	}
}

func (m *Manager) resetFailedAttempts(username string) {
	q := m.dialect.Rebind(QueryResetFailedAttempts)
	if _, err := m.db.Exec(q, username); err != nil {
		m.logger.LogError("failed to reset failed login attempts", "error", err, "username", username)
	}
}

func (m *Manager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}
