package auth

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/o1egl/paseto/v2"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

type Manager struct {
	db           *sql.DB
	dialect      db.Dialect
	paseto       *paseto.V2
	symmetricKey []byte
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

	m := &Manager{
		db:           database,
		dialect:      dialect,
		paseto:       paseto.NewV2(),
		symmetricKey: []byte(symmetricKey),
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
			&user.TwoFactorEnabled, &user.TwoFactorSecret, &recoveryCodes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil, ErrInvalidCredentials
		}
		return "", nil, err
	}

	if recoveryCodes != "" {
		user.RecoveryCodes = strings.Split(recoveryCodes, ",")
	}

	if lockedUntil.Valid && time.Now().Before(lockedUntil.Time) {
		return "", nil, ErrAccountLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)); err != nil {
		m.handleFailedLogin(username, failedAttempts)
		return "", nil, ErrInvalidCredentials
	}

	m.resetFailedAttempts(username)

	if user.TwoFactorEnabled {
		return "", &user, ErrTwoFactorRequired
	}

	return m.issueToken(&user)
}

func (m *Manager) issueToken(user *gateonv1.User) (string, *gateonv1.User, error) {
	now := time.Now()
	exp := now.Add(24 * time.Hour)

	claims := Claims{
		ID:         user.Id,
		Username:   user.Username,
		Role:       user.Role,
		IssuedAt:   now,
		Expiration: exp,
		NotBefore:  now,
	}

	token, err := m.paseto.Encrypt(m.symmetricKey, claims, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to encrypt token: %w", err)
	}

	user.Password = ""
	user.TwoFactorSecret = "" // Don't leak secret
	return token, user, nil
}

func (m *Manager) VerifyToken(token string) (any, error) {
	var claims Claims
	err := m.paseto.Decrypt(token, m.symmetricKey, &claims, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if err := claims.Validate(); err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return &claims, nil
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
		if err := rows.Scan(&u.Id, &u.Username, &u.Role, &u.TwoFactorEnabled); err != nil {
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
	m.symmetricKey = []byte(key)
}

func (m *Manager) Setup2FA(id string) (string, string, []string, error) {
	var user gateonv1.User
	var hashed, role, recoveryCodes string
	var failedAttempts int
	var lockedUntil sql.NullTime

	q := m.dialect.Rebind(QueryUserByID)
	err := m.db.QueryRow(q, id).Scan(&user.Id, &user.Username, &hashed, &role, &failedAttempts, &lockedUntil,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &recoveryCodes)
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

	// Generate recovery codes
	codes := make([]string, 10)
	for i := range 10 {
		codes[i] = uuid.New().String()[:8]
	}

	// Update user with secret but don't enable it yet
	qUpdate := m.dialect.Rebind(QueryUpdate2FA)
	_, err = m.db.Exec(qUpdate, false, key.Secret(), strings.Join(codes, ","), id)
	if err != nil {
		return "", "", nil, err
	}

	var png []byte
	png, err = qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return "", "", nil, err
	}

	qrBase64 := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	return key.Secret(), qrBase64, codes, nil
}

func (m *Manager) Verify2FA(id, code string) (bool, string, *gateonv1.User, error) {
	var user gateonv1.User
	var hashed, role, recoveryCodes string
	var failedAttempts int
	var lockedUntil sql.NullTime

	q := m.dialect.Rebind(QueryUserByID)
	err := m.db.QueryRow(q, id).Scan(&user.Id, &user.Username, &hashed, &role, &failedAttempts, &lockedUntil,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &recoveryCodes)
	if err != nil {
		return false, "", nil, err
	}

	// Check recovery codes first
	if recoveryCodes != "" {
		codes := strings.Split(recoveryCodes, ",")
		for i, c := range codes {
			if c == code {
				// Use code, remove it
				newCodes := append(codes[:i], codes[i+1:]...)
				qUpdate := m.dialect.Rebind(QueryUpdate2FA)
				_, err = m.db.Exec(qUpdate, true, user.TwoFactorSecret, strings.Join(newCodes, ","), id)
				if err != nil {
					return false, "", nil, err
				}
				token, u, err := m.issueToken(&user)
				return true, token, u, err
			}
		}
	}

	valid := totp.Validate(code, user.TwoFactorSecret)
	if valid {
		if !user.TwoFactorEnabled {
			// Enable 2FA on first successful verification
			qUpdate := m.dialect.Rebind(QueryUpdate2FA)
			_, err = m.db.Exec(qUpdate, true, user.TwoFactorSecret, recoveryCodes, id)
			if err != nil {
				return false, "", nil, err
			}
		}
		token, u, err := m.issueToken(&user)
		return true, token, u, err
	}

	return false, "", nil, nil
}

func (m *Manager) Disable2FA(id string) error {
	qUpdate := m.dialect.Rebind(QueryUpdate2FA)
	_, err := m.db.Exec(qUpdate, false, "", "", id)
	return err
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
