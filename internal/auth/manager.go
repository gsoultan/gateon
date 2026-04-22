package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/db"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/o1egl/paseto/v2"
	"golang.org/x/crypto/bcrypt"
)

type Manager struct {
	db           *sql.DB
	dialect      db.Dialect
	paseto       *paseto.V2
	symmetricKey []byte
}

// NewManager creates an auth manager using the given database URL.
func NewManager(databaseURL, symmetricKey string) (*Manager, error) {
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

	q := m.dialect.Rebind(QueryUserByUsername)
	err := m.db.QueryRow(q, username).
		Scan(&user.Id, &user.Username, &hashed, &user.Role, &failedAttempts, &lockedUntil)
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

	m.resetFailedAttempts(username)

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
	return token, &user, nil
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
		return nil, 0, err
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
		return nil, 0, err
	}
	defer rows.Close()

	var users []*gateonv1.User
	for rows.Next() {
		var u gateonv1.User
		if err := rows.Scan(&u.Id, &u.Username, &u.Role); err != nil {
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
			return err
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
		return err
	}
	q := m.dialect.Rebind(QueryInsertUserSQLitePostgresNoPassword)
	_, err := m.db.Exec(q, id, username, "", role)
	return err
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
		return err
	}
	q := m.dialect.Rebind(QueryUpdatePassword)
	_, err = m.db.Exec(q, string(hashed), id)
	return err
}

func (m *Manager) DeleteUser(id string) error {
	q := m.dialect.Rebind(QueryDeleteUser)
	_, err := m.db.Exec(q, id)
	return err
}

func (m *Manager) UpdateSymmetricKey(key string) {
	m.symmetricKey = []byte(key)
}

func (m *Manager) handleFailedLogin(username string, currentAttempts int) {
	var lockedUntil any
	if currentAttempts+1 >= MaxFailedAttempts {
		lockedUntil = time.Now().Add(LockoutDuration)
	}
	q := m.dialect.Rebind(QueryIncrementFailedAttempts)
	_, _ = m.db.Exec(q, lockedUntil, username)
}

func (m *Manager) resetFailedAttempts(username string) {
	q := m.dialect.Rebind(QueryResetFailedAttempts)
	_, _ = m.db.Exec(q, username)
}

func (m *Manager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}
