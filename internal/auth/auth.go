package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/google/uuid"
	"github.com/o1egl/paseto/v2"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// Roles defined for RBAC
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type Manager struct {
	db           *sql.DB
	paseto       *paseto.V2
	symmetricKey []byte
}

type Claims struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	paseto.JSONToken
}

func NewManager(sqlitePath, symmetricKey string) (*Manager, error) {
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping sqlite: %w", err)
	}

	m := &Manager{
		db:           db,
		paseto:       paseto.NewV2(),
		symmetricKey: []byte(symmetricKey),
	}

	if err := m.bootstrap(); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Manager) bootstrap() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := m.db.Exec(query); err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	return nil
}

func (m *Manager) IsSetupDone() bool {
	var count int
	err := m.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

func (m *Manager) Authenticate(username, password string) (string, *gateonv1.User, error) {
	var user gateonv1.User
	var hashed string
	err := m.db.QueryRow("SELECT id, username, password, role FROM users WHERE username = ?", username).
		Scan(&user.Id, &user.Username, &hashed, &user.Role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil, ErrInvalidCredentials
		}
		return "", nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)); err != nil {
		return "", nil, ErrInvalidCredentials
	}

	now := time.Now()
	exp := now.Add(24 * time.Hour)

	claims := Claims{
		ID:       user.Id,
		Username: user.Username,
		Role:     user.Role,
		JSONToken: paseto.JSONToken{
			IssuedAt:   now,
			Expiration: exp,
			NotBefore:  now,
		},
	}

	token, err := m.paseto.Encrypt(m.symmetricKey, claims, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to encrypt token: %w", err)
	}

	// Don't return password in user object
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
	var totalCount int
	err := m.db.QueryRow("SELECT COUNT(*) FROM users WHERE username LIKE ?", "%"+search+"%").Scan(&totalCount)
	if err != nil {
		return nil, 0, err
	}

	query := "SELECT id, username, role FROM users WHERE username LIKE ? ORDER BY username ASC"
	var args []any
	args = append(args, "%"+search+"%")

	if pageSize > 0 {
		query += " LIMIT ? OFFSET ?"
		args = append(args, pageSize, page*pageSize)
	}

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
		_, err = m.db.Exec(`
			INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET username=excluded.username, password=excluded.password, role=excluded.role
			ON CONFLICT(username) DO UPDATE SET password=excluded.password, role=excluded.role`,
			u.Id, u.Username, string(hashed), u.Role)
		return err
	}

	_, err := m.db.Exec(`
		INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET username=excluded.username, role=excluded.role
		ON CONFLICT(username) DO UPDATE SET role=excluded.role`,
		u.Id, u.Username, "", u.Role)
	return err
}

func (m *Manager) DeleteUser(id string) error {
	_, err := m.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

func (m *Manager) UpdateSymmetricKey(key string) {
	m.symmetricKey = []byte(key)
}

func (m *Manager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}
