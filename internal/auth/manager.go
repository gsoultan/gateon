// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
	db      *sql.DB
	dialect db.Dialect
	// keys are what the PASETO secret becomes. Swapped whole, atomically, by
	// UpdateSymmetricKey; read without a lock on every verify.
	keys atomic.Pointer[sessionKeys]
	// secondFactorMu orders a key rotation against the use of a stored second
	// factor: the rotation re-encrypts every one and swaps the key, and
	// nothing may encrypt or decrypt one in between.
	secondFactorMu sync.RWMutex
	parser         paseto.Parser
	logger         logger.Logger
	bindings       *bindingCache

	// bindingPub is installed after construction (SetBindingPublisher) so the
	// trust boundary's constructor gains no broker dependency. nil means no
	// propagation, which is the default and the single-instance case.
	bindingPub atomic.Pointer[BindingPublisher]
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

	keys, err := deriveSessionKeys(symmetricKey)
	if err != nil {
		_ = database.Close()
		return nil, err
	}

	m := &Manager{
		db:       database,
		dialect:  dialect,
		parser:   paseto.NewParser(),
		logger:   l,
		bindings: newBindingCache(),
	}
	m.keys.Store(keys)

	return m, nil
}

// ErrSessionKeyTooShort refuses a PASETO secret shorter than a v4 local key.
var ErrSessionKeyTooShort = errors.New("PASETO v4 symmetric key must be at least 32 bytes")

// sessionKeys are what the PASETO secret becomes: the key that signs every
// session and the key that encrypts each second factor at rest. They are the
// same 32 bytes, and replaced together, so no request sees one from one secret
// and the other from another.
type sessionKeys struct {
	sign paseto.V4SymmetricKey
	enc  []byte
}

func deriveSessionKeys(secret string) (*sessionKeys, error) {
	b := []byte(secret)
	if len(b) < 32 {
		return nil, ErrSessionKeyTooShort
	}
	sign, err := paseto.V4SymmetricKeyFromBytes(b[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create PASETO v4 key: %w", err)
	}
	return &sessionKeys{sign: sign, enc: append([]byte(nil), b[:32]...)}, nil
}

// IsSetupDone reports whether an administrator account exists.
//
// A failed read answers true. IsSetupRequired turns this into "may Setup run",
// and Setup -- public, served before authentication -- creates an administrator
// and installs the caller's PASETO secret. This used to answer with rows.Next(),
// which is false for an empty table and equally false for a query that failed,
// so a locked SQLite file, a restarting Postgres or an exhausted pool read as
// "no users yet" and reopened Setup on a configured gateway for as long as the
// error lasted. Only sql.ErrNoRows means the table is empty.
func (m *Manager) IsSetupDone() bool {
	var one int
	err := m.db.QueryRow(m.dialect.Rebind(QueryCountUsers)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		m.logger.LogError("cannot tell whether an administrator exists; first-run setup "+
			"stays closed until the user table can be read", "error", err)
	}
	return true
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

	if user.Role == "" {
		user.Role = RoleViewer
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

// TokenLifetime is how long an issued session token stays valid.
//
// It was 24 hours. A bearer token with no server-side state is only as
// revocable as it is short-lived, and even with the session binding added in
// revocation.go the window matters: the binding covers disable, delete, role
// change and password change, but not "this laptop was stolen and nobody has
// noticed yet". Eight hours bounds that to a working day without forcing a
// re-login over a lunch break.
const TokenLifetime = 8 * time.Hour

func (m *Manager) issueToken(user *gateonv1.User) (string, *gateonv1.User, error) {
	// Bind the token to the account state it was issued against, so any later
	// change to that state invalidates it. Read through the cache-backed helper
	// rather than recomputing here: it is the same value VerifyToken will
	// compare against, and deriving it in two places invites them to drift.
	binding, err := m.currentBinding(user.Id)
	if err != nil {
		return "", nil, err
	}

	token := paseto.NewToken()
	now := time.Now()
	exp := now.Add(TokenLifetime)

	token.SetExpiration(exp)
	token.SetIssuedAt(now)
	token.SetNotBefore(now)
	token.SetSubject(user.Id)
	token.SetString("id", user.Id)
	token.SetString("username", user.Username)
	token.SetString("role", user.Role)
	token.SetString(SessionBindingClaim, binding)

	encrypted := token.V4Encrypt(m.keys.Load().sign, nil)

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
	parsedToken, err := m.parser.ParseV4Local(m.keys.Load().sign, token, nil)
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
	if val, err := parsedToken.GetString(SessionBindingClaim); err == nil {
		claims.SessionBinding = val
	}

	if err := claims.Validate(); err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Cryptographic validity is not authorization. Consult the account the
	// token was issued for: disabled, deleted, demoted or re-passworded users
	// must lose their live sessions here, not whenever the token happens to
	// expire.
	if err := m.checkSessionBinding(claims.ID, claims.SessionBinding); err != nil {
		return nil, err
	}

	return claims, nil
}

// revokeSessions ends every live session for a user by dropping the cached
// binding, so the next request re-reads the account and finds the mismatch.
// Every mutation of a session-binding input must call this.
func (m *Manager) revokeSessions(id string) {
	if id == "" || m.bindings == nil {
		return
	}
	m.bindings.invalidate(id)

	// Local first, then the peers. The local drop is the part that has to
	// happen; the publish turns a sibling's delay from up to DefaultBindingTTL
	// into a round trip, and its failure leaves the TTL doing what it does now.
	m.publishBindingRevocation(id)
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

// UpsertUser creates u, or edits the account u.Id names.
//
// Creates and edits share it -- the API has one UpdateUser for both -- and it
// used to be one statement for both, INSERT ... ON CONFLICT(username) DO
// UPDATE SET password, role. A create under a username that existed therefore
// replaced that account's password and role and reported success: from Add
// User, an administrator who typed a colleague's name took over their account.
//
// An edit now writes by id, and anything else -- no id, or an id no account
// has -- is a create, a plain INSERT. A username that is taken, by a create or
// by an edit renaming onto it, is refused with ErrUsernameTaken and nothing is
// written. The table's unique constraint refuses it rather than a lookup
// beforehand, so two requests racing for one name cannot both win.
func (m *Manager) UpsertUser(u *gateonv1.User) error {
	if u.Role == "" {
		u.Role = RoleViewer
	} else if !ValidRole(u.Role) {
		return fmt.Errorf("invalid role: %s", u.Role)
	}
	hashed, err := hashPassword(u.Password)
	if err != nil {
		return err
	}
	if u.Id != "" {
		if updated, err := m.updateUser(u, hashed); err != nil || updated {
			return err
		}
	} else {
		u.Id = uuid.New().String()
	}
	return m.insertUser(u, hashed)
}

// hashPassword returns the bcrypt hash of password, or "" for no password.
func hashPassword(password string) (string, error) {
	if password == "" {
		return "", nil
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashed), nil
}

// updateUser writes u's username, role and -- when hashed is not empty --
// password to the account u.Id names, and reports whether there is one. It is
// the one place an existing account is edited, so it is where the session
// binding is invalidated: a role change is a privilege change, and demoting an
// administrator must not leave them holding an administrator's token.
func (m *Manager) updateUser(u *gateonv1.User, hashed string) (bool, error) {
	q, args := QueryUpdateUser, []any{u.Username, u.Role, u.Id}
	if hashed != "" {
		q, args = QueryUpdateUserWithPassword, []any{u.Username, hashed, u.Role, u.Id}
	}
	res, err := m.db.Exec(m.dialect.Rebind(q), args...)
	if err != nil {
		return false, userWriteError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to update user: %w", err)
	}
	if n == 0 {
		return false, nil
	}
	m.revokeSessions(u.Id)
	return true, nil
}

// insertUser creates u. A new account has no session to revoke.
func (m *Manager) insertUser(u *gateonv1.User, hashed string) error {
	q := m.dialect.Rebind(QueryInsertUser)
	if _, err := m.db.Exec(q, u.Id, u.Username, hashed, u.Role); err != nil {
		return userWriteError(err)
	}
	return nil
}

// userWriteError names a unique-constraint refusal for what it means to the
// caller, and wraps anything else. The one unique column besides the id is the
// username; the id collides only when two creates race under one chosen id,
// where the answer -- someone else has it -- is the same.
func userWriteError(err error) error {
	if db.IsUniqueViolation(err) {
		return ErrUsernameTaken
	}
	return fmt.Errorf("failed to save user: %w", err)
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
	// A password rotation is usually a response to a suspected compromise.
	// Leaving sessions minted under the old password alive would defeat the
	// point of rotating it.
	m.revokeSessions(id)
	return nil
}

// ChangeOwnPassword changes account id's password for a caller who presents
// the current one, checked by confirmPassword under login's rules and lockout.
//
// ChangePassword alone needs nothing but an id, which was all a signed-in user
// changing their own password had to supply -- so the session was enough, and in
// the dashboard the session is a cookie that script in the page can ride. A
// password chosen by that script would outlive the session it was set from.
func (m *Manager) ChangeOwnPassword(id, current, password string) error {
	if err := m.confirmPassword(id, current); err != nil {
		return err
	}
	return m.ChangePassword(id, password)
}

func (m *Manager) DeleteUser(id string) error {
	q := m.dialect.Rebind(QueryDeleteUser)
	_, err := m.db.Exec(q, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	// The row is gone, so the next binding lookup finds no rows and denies.
	// Dropping the cached entry is what forces that lookup to happen.
	m.revokeSessions(id)
	return nil
}

// UpdateSymmetricKey makes key the session key, now. Every session signed with
// the previous key ends -- that is what rotating it is for. Every stored second
// factor, which is encrypted at rest under the same key, is re-encrypted under
// the new one first, in one transaction, so no account loses its enrolment; a
// rotation that left them behind would lock every 2FA account out, the
// administrator who rotated included. A key shorter than 32 bytes is refused,
// and so is a rotation whose re-encryption fails; either way the previous key
// stays in force. The same key again changes nothing.
//
// It used to swap the key unsynchronised against every verify, ignore a short
// key without a word, and leave the second factors encrypted under the old one.
// Nothing called it after setup, so a key saved in Settings changed nothing
// until the next restart -- and the restart then ended every 2FA login.
func (m *Manager) UpdateSymmetricKey(key string) error {
	next, err := deriveSessionKeys(key)
	if err != nil {
		return err
	}
	m.secondFactorMu.Lock()
	defer m.secondFactorMu.Unlock()
	current := m.keys.Load()
	if bytes.Equal(current.enc, next.enc) {
		return nil
	}
	if err := m.reencryptSecondFactors(current.enc, next.enc); err != nil {
		return fmt.Errorf("rotate the session key: %w", err)
	}
	m.keys.Store(next)
	return nil
}

// reencryptSecondFactors rewrites every stored second factor from key from to
// key to, in one transaction.
func (m *Manager) reencryptSecondFactors(from, to []byte) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stored, err := secondFactorSecrets(tx, m.dialect)
	if err != nil {
		return err
	}
	update := m.dialect.Rebind(QueryUpdateTwoFactorSecret)
	for id, secret := range stored {
		plain, err := decryptSecret(from, secret)
		if err != nil {
			// It does not decrypt under the key in force either, so the account
			// could not sign in with it before the rotation; nothing is lost.
			m.logger.LogWarn("a stored second factor does not decrypt under the session key; the account must enrol again",
				"user", id)
			continue
		}
		enc, err := encryptSecret(to, plain)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(update, enc, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func secondFactorSecrets(tx *sql.Tx, d db.Dialect) (map[string]string, error) {
	rows, err := tx.Query(d.Rebind(QueryTwoFactorSecrets))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	stored := map[string]string{}
	for rows.Next() {
		var id, secret string
		if err := rows.Scan(&id, &secret); err != nil {
			return nil, err
		}
		stored[id] = secret
	}
	return stored, rows.Err()
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

	secret, qr, codes, err := m.beginTOTPEnrolment(id)
	if err != nil {
		return "", "", nil, "", err
	}
	return secret, qr, codes, id, nil
}

// Setup2FA begins self-service TOTP enrolment for account id, and only for a
// caller who presents that account's current password.
//
// It used to need nothing but the id, which the handler checks against the
// session -- so holding the session was enough to enrol, and in the dashboard
// script can hold the session without being able to read it: the stored-XSS
// case the HttpOnly cookie exists for. Script could call setup, keep the secret
// it was handed, verify a code derived from it, and leave the account's second
// factor in an authenticator it controls (on an enrolled account, in place of
// the owner's). The password is the one thing script in the page does not have.
func (m *Manager) Setup2FA(id, password string) (string, string, []string, error) {
	if err := m.confirmPassword(id, password); err != nil {
		return "", "", nil, err
	}
	return m.beginTOTPEnrolment(id)
}

// confirmPassword applies login's first-factor rules to an account that is
// already signed in, in Authenticate's order: a locked account is refused
// before the password is compared, a wrong password counts towards the same
// lockout the sign-in form enforces, a disabled account is refused only after
// a correct one, and a correct one clears the count. Anything looser would make
// a re-authentication prompt a faster way to guess the password than the
// sign-in form -- one an attacker who holds a session reaches without a
// captcha, a rate limit or a login audit entry.
func (m *Manager) confirmPassword(id, password string) error {
	var uid, username, hashed, role, secret, recoveryCodes string
	var failedAttempts int
	var lockedUntil sql.NullTime
	var twoFactorEnabled, disabled, twoFactorPending bool

	q := m.dialect.Rebind(QueryUserByID)
	err := m.db.QueryRow(q, id).Scan(&uid, &username, &hashed, &role, &failedAttempts, &lockedUntil,
		&twoFactorEnabled, &secret, &recoveryCodes, &disabled, &twoFactorPending)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidCredentials
	}
	if err != nil {
		return err
	}
	if lockedUntil.Valid && time.Now().Before(lockedUntil.Time) {
		return ErrAccountLocked
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)); err != nil {
		m.handleFailedLogin(username, failedAttempts)
		return ErrInvalidCredentials
	}
	if disabled {
		return ErrAccountDisabled
	}
	m.resetFailedAttempts(username)
	return nil
}

// beginTOTPEnrolment generates a TOTP secret and recovery codes for account id
// and stores them, not yet enabled; Verify2FA enables them. Every caller must
// already have established the account's first factor: Setup2FA by the
// password, EnrollPending2FA by the password during a mandated sign-in.
func (m *Manager) beginTOTPEnrolment(id string) (string, string, []string, error) {
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

	// Encrypt the TOTP secret at rest and store it, not yet enabled, under a key
	// a rotation cannot swap until the write is done.
	m.secondFactorMu.RLock()
	encSecret, err := encryptSecret(m.keys.Load().enc, key.Secret())
	if err == nil {
		_, err = m.db.Exec(m.dialect.Rebind(QueryUpdate2FA), false, encSecret, strings.Join(hashedCodes, ","), id)
	}
	m.secondFactorMu.RUnlock()
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
	// Held while the stored secret is read, decrypted and written back, so a
	// key rotation cannot re-encrypt it in between.
	m.secondFactorMu.RLock()
	defer m.secondFactorMu.RUnlock()
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
	plainSecret, err := decryptSecret(m.keys.Load().enc, storedSecret)
	if err != nil {
		return false, "", nil, err
	}

	// An account that never enrolled has no secret, and the column defaults to
	// "" rather than NULL. totp.Validate does not refuse an empty secret: it
	// base32-decodes "" to an empty HMAC key and accepts the six-digit code
	// derived from it, which is the same code for every unenrolled account. So
	// the absence of a secret has to be refused here, before the library sees
	// it, or this path mints a session for any account by id with no password.
	if plainSecret == "" {
		m.handleFailedLogin(user.Username, failedAttempts)
		return false, "", nil, ErrInvalidTwoFactorCode
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
	// Disabling an account is the one action an operator takes expecting it to
	// be immediate — it is what you do when someone leaves or an account is
	// suspected compromised. Until this call existed it only set a column that
	// nothing on the request path ever read.
	m.revokeSessions(id)
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
		// UTC, because locked_until is TIMESTAMP without time zone on
		// Postgres: the offset of a local time is dropped on the way in and
		// the wall clock comes back as UTC, so on a host behind UTC the lock
		// was already over when it was read and the account never locked.
		lockedUntil = time.Now().UTC().Add(LockoutDuration)
	}
	q := m.dialect.Rebind(QueryIncrementFailedAttempts)
	if _, err := m.db.Exec(q, lockedUntil, username); err != nil {
		// Logged at error, and named for what it costs. While this write is
		// failing the counter never advances, so MaxFailedAttempts and
		// LockoutDuration do not apply and the account is open to unlimited
		// guessing -- while login keeps answering with an ordinary invalid
		// credentials response, so nothing upstream can tell.
		m.logger.LogError("brute-force lockout not recorded; failed attempts are "+
			"not being counted and the account cannot lock",
			"error", err, "username", username,
			"max_failed_attempts", MaxFailedAttempts)
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

func (m *Manager) DB() *sql.DB {
	return m.db
}

func (m *Manager) Dialect() db.Dialect {
	return m.dialect
}
