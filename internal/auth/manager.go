// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/auth/admission"
	"github.com/gsoultan/gateon/internal/auth/apitoken"
	"github.com/gsoultan/gateon/internal/auth/lockout"
	"github.com/gsoultan/gateon/internal/auth/passpolicy"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/pquerna/otp"
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

	// knownAttempts and unknownAttempts count failed password attempts
	// (ADR 0050): for accounts that exist, keyed by id, and for usernames that
	// do not, so the two answer alike and invented names cannot evict a real
	// account's count. In memory, per instance; bounded by lockout.DefaultBounds.
	knownAttempts   *lockout.Tracker
	unknownAttempts *lockout.Tracker

	// hashes bounds the bcrypt work running at once (ADR 0053): every
	// comparison and every hash this manager makes takes a slot first.
	hashes *admission.Gate

	// tokens holds the scrape credentials (ADR 0050).
	tokens *apitoken.Store

	// now is the clock TOTP codes are checked against; time.Now but in tests.
	now func() time.Time
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
		db:              database,
		dialect:         dialect,
		parser:          paseto.NewParser(),
		logger:          l,
		bindings:        newBindingCache(),
		knownAttempts:   lockout.New(lockout.DefaultBounds),
		unknownAttempts: lockout.New(lockout.DefaultBounds),
		hashes:          admission.NewGate(admission.HashConcurrency()),
		tokens:          apitoken.NewStore(database, dialect),
		now:             time.Now,
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

// Authenticate is a password sign-in from source, the caller's address.
func (m *Manager) Authenticate(username, password, source string) (string, *gateonv1.User, error) {
	row, err := m.checkFirstFactor(username, password, source)
	if err != nil {
		return "", nil, err
	}
	user := &row.user

	if user.TwoFactorEnabled {
		return m.owedSecondFactor(user, ErrTwoFactorRequired)
	}

	// An administrator mandated 2FA but the user has not enrolled yet: do not issue
	// a session. The client must run first-time TOTP enrollment (EnrollPending2FA,
	// then Verify2FA with the challenge) before login completes. The user id is
	// returned (no secret) so the client knows which account to enroll.
	if user.TwoFactorPending {
		return m.owedSecondFactor(user, ErrTwoFactorSetupRequired)
	}

	return m.issueToken(user)
}

// loginRow is the account a password sign-in names, as the first factor reads it.
type loginRow struct {
	user   gateonv1.User
	hashed string
}

// loadLoginRow reads username's account, or nil when there is none.
func (m *Manager) loadLoginRow(username string) (*loginRow, error) {
	var row loginRow
	var recoveryCodes string
	var failedAttempts int
	var lockedUntil sql.NullTime
	err := m.db.QueryRow(m.dialect.Rebind(QueryUserByUsername), username).
		Scan(&row.user.Id, &row.user.Username, &row.hashed, &row.user.Role, &failedAttempts, &lockedUntil,
			&row.user.TwoFactorEnabled, &row.user.TwoFactorSecret, &recoveryCodes,
			&row.user.Disabled, &row.user.TwoFactorPending)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if row.user.Role == "" {
		row.user.Role = RoleViewer
	}
	return &row, nil
}

// checkFirstFactor is the password step of a sign-in and of a mandated
// enrolment, under the lockout of ADR 0050, and returns the account it proved.
//
// An unknown username takes the same path as a known one -- the same attempt
// counting, the same lock answers, and a bcrypt comparison at the stored cost
// -- so neither the answer nor its timing says whether the account exists.
// Unknown names used to answer in 1-8 ms and real ones in about 55, and only a
// real one could ever answer "locked".
//
// A disabled account is refused only after a correct password, so the refusal
// does not tell a guesser which accounts are disabled.
//
// It does not touch the stored failure count. That count is the second
// factor's (Verify2FA) and the re-authentication prompt's (confirmPassword):
// the password step reset it on every correct password, so whoever held the
// password could sign in again after every fourth wrong code and guess TOTP
// codes without ever locking.
func (m *Manager) checkFirstFactor(username, password, addr string) (*loginRow, error) {
	row, err := m.loadLoginRow(username)
	if err != nil {
		return nil, err
	}
	source := lockout.Prefix(addr)
	tracker, key := m.trackerFor(row, username)
	if err := m.admit(row, tracker, key, source); err != nil {
		return nil, err
	}
	slot, err := m.enterForSignIn(row, source)
	if err != nil {
		return nil, err
	}
	match := passwordMatches(row, password)
	slot.Release()
	if !match {
		tracker.Fail(key, source)
		return nil, ErrInvalidCredentials
	}
	if row.user.Disabled {
		return nil, ErrAccountDisabled
	}
	tracker.Succeed(key, source)
	m.rememberSource(row.user.Id, source)
	return row, nil
}

// trackerFor is the tracker and key an attempt is counted under. Accounts
// that exist are keyed by id in a tracker only they reach, so a flood of
// invented usernames cannot evict a real account's count.
func (m *Manager) trackerFor(row *loginRow, username string) (*lockout.Tracker, string) {
	if row == nil {
		return m.unknownAttempts, username
	}
	return m.knownAttempts, row.user.Id
}

// admit refuses an attempt the lockout does not allow. An account under attack
// still admits a source it has signed in from before: that is what keeps the
// owner in while strangers are kept out.
func (m *Manager) admit(row *loginRow, tracker *lockout.Tracker, key, source string) error {
	switch tracker.Check(key, source) {
	case lockout.Allow:
		return nil
	case lockout.PairLocked:
		return ErrAccountLocked
	}
	if row != nil && m.isKnownSource(row.user.Id, source) {
		return nil
	}
	tracker.Renew(key)
	return ErrAccountLocked
}

// enterForSignIn takes a hash slot for a password step, or refuses it as
// ErrBusy at once: an anonymous attempt never waits (ADR 0053). When every
// general slot is taken, the reserve is held back for an account's own known
// source, so a flood from addresses the account has never signed in from --
// however many -- cannot keep its owner out. The refusal comes before any hash,
// and an unknown username is refused exactly as a real one from a source it
// does not know.
func (m *Manager) enterForSignIn(row *loginRow, source string) (admission.Slot, error) {
	if s, ok := m.hashes.TryEnter(); ok {
		return s, nil
	}
	if row != nil && m.isKnownSource(row.user.Id, source) {
		if s, ok := m.hashes.TryEnterReserved(); ok {
			return s, nil
		}
	}
	return admission.Slot{}, ErrBusy
}

// withHashSlot runs fn, which hashes for a signed-in caller or for one who
// has already proved the password, in a hash slot it waits up to
// signedInHashWait for; ErrBusy if none came free.
func (m *Manager) withHashSlot(fn func() error) error {
	slot, ok := m.hashes.Enter(signedInHashWait)
	if !ok {
		return ErrBusy
	}
	defer slot.Release()
	return fn()
}

// dummyHash is compared against when there is no stored hash to compare
// against, at the cost passwords are stored at, so a sign-in for an account
// that does not exist takes as long as one for an account that does.
var dummyHash = sync.OnceValue(func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("gateon: no such account"), productionBcryptCost)
	if err != nil {
		return nil
	}
	return h
})

// passwordMatches reports whether password is row's. With no row, or no
// stored hash, it still pays for one comparison and answers false.
func passwordMatches(row *loginRow, password string) bool {
	if row == nil || row.hashed == "" {
		_ = compareHash(dummyHash(), []byte(password))
		return false
	}
	return compareHash([]byte(row.hashed), []byte(password)) == nil
}

// maxLoginSources is how many source prefixes an account remembers.
const maxLoginSources = 8

// isKnownSource reports whether account id has signed in from source before.
// "" -- an address that did not parse -- is never known.
func (m *Manager) isKnownSource(id, source string) bool {
	if source == "" {
		return false
	}
	return slices.Contains(m.loginSources(id), source)
}

func (m *Manager) loginSources(id string) []string {
	var stored string
	if err := m.db.QueryRow(m.dialect.Rebind(QueryLoginSources), id).Scan(&stored); err != nil {
		return nil
	}
	if stored == "" {
		return nil
	}
	return strings.Split(stored, ",")
}

// rememberSource records that account id signed in from source, keeping the
// maxLoginSources most recent. A source already known is not rewritten, so an
// ordinary sign-in costs a read and no write.
func (m *Manager) rememberSource(id, source string) {
	if source == "" {
		return
	}
	known := m.loginSources(id)
	if slices.Contains(known, source) {
		return
	}
	known = append([]string{source}, known...)
	if len(known) > maxLoginSources {
		known = known[:maxLoginSources]
	}
	if _, err := m.db.Exec(m.dialect.Rebind(QueryUpdateLoginSources), strings.Join(known, ","), id); err != nil {
		m.logger.LogError("could not record a sign-in source; under attack this account "+
			"will not be admitted from it", "error", err)
	}
}

// APITokens is the scrape-credential store (ADR 0050).
func (m *Manager) APITokens() *apitoken.Store {
	return m.tokens
}

// owedSecondFactor answers a correct password on an account that still owes a
// second factor: no session, the account (stripped of its secrets) and a
// *SecondStepError wrapping owed that carries the challenge Verify2FA requires.
// The challenge is how the second step knows the first one happened; without it
// an account id and one code were a whole sign-in. See ADR 0039.
func (m *Manager) owedSecondFactor(user *gateonv1.User, owed error) (string, *gateonv1.User, error) {
	sanitizeUser(user)
	challenge, err := m.issueChallenge(user.Id, time.Now())
	if err != nil {
		return "", nil, err
	}
	return "", user, &SecondStepError{Err: owed, Challenge: challenge}
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
	// A session has no purpose claim. A token that has one was minted under
	// this key for something else -- a two-factor challenge proves a password,
	// not a sign-in -- and is never a session, whatever else it carries.
	if _, err := parsedToken.GetString(PurposeClaim); err == nil {
		return nil, fmt.Errorf("invalid token: %w", errNotASession)
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
//
// A password, when one is given, must pass passpolicy.Check, and a create must
// give one: there was no rule, so "a" was accepted and a create with no
// password stored an empty hash (ADR 0050). An edit without one keeps the
// account's password.
func (m *Manager) UpsertUser(u *gateonv1.User) error {
	if u.Role == "" {
		u.Role = RoleViewer
	} else if !ValidRole(u.Role) {
		return fmt.Errorf("invalid role: %s", u.Role)
	}
	if u.Password != "" {
		if err := passpolicy.Check(u.Password, u.Username); err != nil {
			return err
		}
	}
	var hashed string
	err := m.withHashSlot(func() (err error) {
		hashed, err = hashPassword(u.Password)
		return err
	})
	if err != nil {
		return err
	}
	if u.Id != "" {
		if updated, err := m.updateUser(u, hashed); err != nil || updated {
			return err
		}
	}
	if hashed == "" {
		return passpolicy.ErrEmpty
	}
	if u.Id == "" {
		u.Id = uuid.New().String()
	}
	return m.insertUser(u, hashed)
}

// hashPassword returns the bcrypt hash of password, or "" for no password.
func hashPassword(password string) (string, error) {
	if password == "" {
		return "", nil
	}
	hashed, err := generateHash([]byte(password), bcryptCost)
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

// ChangePassword sets account id's password, which must pass passpolicy.Check.
func (m *Manager) ChangePassword(id, password string) error {
	if err := m.checkNewPassword(id, password); err != nil {
		return err
	}
	return m.setPassword(id, password)
}

// checkNewPassword applies the password policy to password for account id.
func (m *Manager) checkNewPassword(id, password string) error {
	var username string
	if err := m.db.QueryRow(m.dialect.Rebind(QueryUsernameByID), id).Scan(&username); err != nil &&
		!errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to read user: %w", err)
	}
	return passpolicy.Check(password, username)
}

func (m *Manager) setPassword(id, password string) error {
	var hashed []byte
	err := m.withHashSlot(func() (err error) {
		hashed, err = generateHash([]byte(password), bcryptCost)
		return err
	})
	if errors.Is(err, ErrBusy) {
		return err
	}
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
//
// The new password is checked against the policy first, so a refused one does
// not spend a guess at the current one.
func (m *Manager) ChangeOwnPassword(id, current, password string) error {
	if err := m.checkNewPassword(id, password); err != nil {
		return err
	}
	if err := m.confirmPassword(id, current); err != nil {
		return err
	}
	return m.setPassword(id, password)
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
	if _, err := m.moveSecondFactors(current.enc, next.enc); err != nil {
		return fmt.Errorf("rotate the session key: %w", err)
	}
	m.keys.Store(next)
	return nil
}

// SecondFactorKeyReport says what a pass over the stored second factors did.
type SecondFactorKeyReport struct {
	// Moved were re-encrypted under the session key in force: from the other
	// key, or from a plaintext secret stored before encryption at rest.
	Moved int
	// Unreadable decrypt under neither key. Those accounts cannot complete a
	// 2FA sign-in until they enrol again.
	Unreadable int
}

// ReconcileSecondFactors moves under the session key in force every stored
// second factor encrypted under previousKey, and reports those that decrypt
// under neither. previousKey only ever decrypts second factors: it never
// verifies a session, so a key that was rotated away stays rotated away.
//
// Only a rotation through UpdateSymmetricKey re-encrypts them. A key changed any
// other way -- global.json edited, the $env or vault reference it names rotated
// at the source, one node of a cluster restarted with its peers' new key -- left
// every enrolment unreadable, and each 2FA account unable to sign in, with
// nothing to say why. The gateway runs this at startup, with the previous key
// from GATEON_PREVIOUS_SESSION_KEY when the operator sets it. A factor already
// under the key in force is left alone, so every node of a cluster can run it:
// the first to start moves them, the others find nothing to do.
func (m *Manager) ReconcileSecondFactors(previousKey string) (SecondFactorKeyReport, error) {
	var previous []byte
	if previousKey != "" {
		keys, err := deriveSessionKeys(previousKey)
		if err != nil {
			return SecondFactorKeyReport{}, fmt.Errorf("the previous session key: %w", err)
		}
		previous = keys.enc
	}
	m.secondFactorMu.Lock()
	defer m.secondFactorMu.Unlock()
	return m.moveSecondFactors(previous, m.keys.Load().enc)
}

// moveSecondFactors re-encrypts under to, in one transaction, every stored
// second factor that is not already encrypted under it: one encrypted under
// from, or a plaintext one. The caller holds secondFactorMu.
func (m *Manager) moveSecondFactors(from, to []byte) (SecondFactorKeyReport, error) {
	var report SecondFactorKeyReport
	tx, err := m.db.Begin()
	if err != nil {
		return report, err
	}
	defer func() { _ = tx.Rollback() }()
	stored, err := secondFactorSecrets(tx, m.dialect)
	if err != nil {
		return report, err
	}
	update := m.dialect.Rebind(QueryUpdateTwoFactorSecret)
	for id, secret := range stored {
		if encryptedUnder(to, secret) {
			continue
		}
		plain, err := decryptSecret(from, secret)
		if err != nil {
			// Under neither key: the account could not complete a 2FA sign-in
			// before this pass either, and must enrol again.
			m.logger.LogWarn("a stored second factor does not decrypt under the session key; the account must enrol again",
				"user", id)
			report.Unreadable++
			continue
		}
		enc, err := encryptSecret(to, plain)
		if err != nil {
			return report, err
		}
		if _, err := tx.Exec(update, enc, id); err != nil {
			return report, err
		}
		report.Moved++
	}
	return report, tx.Commit()
}

// encryptedUnder reports whether stored is encrypted, and under key. A
// plaintext secret is not: decryptSecret hands it back under any key.
func encryptedUnder(key []byte, stored string) bool {
	if !strings.HasPrefix(stored, encPrefix) {
		return false
	}
	_, err := decryptSecret(key, stored)
	return err == nil
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
//
// Its password step is the sign-in's, checkFirstFactor, under the same lockout
// and from the same source: it is as public as /v1/login.
func (m *Manager) EnrollPending2FA(username, password, source string) (string, string, []string, string, error) {
	row, err := m.checkFirstFactor(username, password, source)
	if err != nil {
		return "", "", nil, "", err
	}
	// Enrollment via this unauthenticated path is only for accounts an admin
	// mandated 2FA for and that haven't enrolled. Anything else must go through the
	// authenticated self-service Setup2FA endpoint.
	if row.user.TwoFactorEnabled || !row.user.TwoFactorPending {
		return "", "", nil, "", ErrInvalidCredentials
	}
	id := row.user.Id
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
//
// The challenge it returns completes the enrolment through Verify2FA, which
// requires one for every caller: this is where the password was shown.
func (m *Manager) Setup2FA(id, password string) (Enrolment, error) {
	if err := m.confirmPassword(id, password); err != nil {
		return Enrolment{}, err
	}
	secret, qr, codes, err := m.beginTOTPEnrolment(id)
	if err != nil {
		return Enrolment{}, err
	}
	challenge, err := m.issueChallenge(id, time.Now())
	if err != nil {
		return Enrolment{}, err
	}
	return Enrolment{Secret: secret, QRCodeURL: qr, RecoveryCodes: codes, Challenge: challenge}, nil
}

// Enrolment is what Setup2FA hands the account starting a TOTP enrolment.
type Enrolment struct {
	Secret        string
	QRCodeURL     string
	RecoveryCodes []string
	// Challenge proves the password Setup2FA was given; Verify2FA requires it.
	Challenge string
}

// confirmPassword applies login's first-factor rules to an account that is
// already signed in: a locked account is refused before the password is
// compared, a wrong password counts towards a lock of MaxFailedAttempts per
// LockoutDuration, a disabled account is refused only after a correct one, and
// a correct one clears the count. Anything looser would make a
// re-authentication prompt a faster way to guess the password than the sign-in
// form -- one an attacker who holds a session reaches without a captcha, a
// rate limit or a login audit entry.
//
// The count is the stored one the second factor also uses, not the sign-in
// form's (ADR 0050). They used to be one count, so a session in hostile hands
// could lock the owner out of signing in, and anyone could lock the owner out
// of this prompt and of the second factor by guessing at the sign-in form.
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
	var mismatch error
	if err := m.withHashSlot(func() error {
		mismatch = compareHash([]byte(hashed), []byte(password))
		return nil
	}); err != nil {
		return err
	}
	if mismatch != nil {
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
	var plainCodes, hashedCodes []string
	err = m.withHashSlot(func() (err error) {
		plainCodes, hashedCodes, err = generateRecoveryCodes()
		return err
	})
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

// completeSecondFactor issues the session for a correct second factor. A
// disabled account is refused here, after the code was accepted, for the same
// reason Login refuses it only after a correct password: so the refusal does not
// tell a caller without the code which accounts are disabled. Verify2FA is
// reachable on its own with an account id, so without this a disabled user who
// still held their authenticator or a recovery code signed straight back in.
func (m *Manager) completeSecondFactor(user *gateonv1.User) (bool, string, *gateonv1.User, error) {
	if user.Disabled {
		return false, "", nil, ErrAccountDisabled
	}
	m.resetFailedAttempts(user.Username)
	token, u, err := m.issueToken(user)
	return err == nil, token, u, err
}

// Verify2FA is the second step of a sign-in, and the last step of an
// enrolment: a code for account id, with the challenge that proves the
// password step (Authenticate's SecondStepError, or Setup2FA's Enrolment).
//
// The challenge is checked first, and a refusal is ErrInvalidChallenge whatever
// the reason. It is not counted towards the lockout and does not consult it: a
// caller without a challenge has not guessed at anything the account owns, and
// counting it would let anyone who knows an id lock that account out. Only a
// caller who has shown the password gets as far as the code, and only there do
// wrong codes count. See ADR 0039.
func (m *Manager) Verify2FA(challenge, id, code string) (bool, string, *gateonv1.User, error) {
	if err := m.checkChallenge(challenge, id); err != nil {
		return false, "", nil, err
	}
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
	// The session issued below reads its role claim from user.Role. Leaving it
	// in the local variable signed every 2FA account in with role "", which
	// every permission check refuses.
	user.Role = role

	// The stored lock throttles guesses at the 6-digit TOTP and recovery codes.
	// Only a caller who has shown the password reaches here, and the password
	// step no longer clears this count (ADR 0050).
	if lockedUntil.Valid && time.Now().Before(lockedUntil.Time) {
		return false, "", nil, ErrAccountLocked
	}

	// The stored secret is encrypted at rest; user keeps the stored form for
	// persistence and a copy is decrypted for validation.
	plainSecret, err := decryptSecret(m.keys.Load().enc, user.TwoFactorSecret)
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

	ok, err := m.acceptCode(&user, plainSecret, recoveryCodes, code)
	if err != nil {
		return false, "", nil, err
	}
	if ok {
		return m.completeSecondFactor(&user)
	}
	// Invalid code: count it towards the lockout threshold.
	m.handleFailedLogin(user.Username, failedAttempts)
	return false, "", nil, ErrInvalidTwoFactorCode
}

// totpOpts are totp.Validate's defaults: 30-second steps, six digits, SHA-1,
// and one step of skew either way.
var totpOpts = totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// acceptCode reports whether code is the account's current TOTP code -- which
// completes an enrolment -- or one of its unused recovery codes, which it
// spends. user.TwoFactorSecret is the stored, encrypted secret.
//
// The TOTP code is checked first. The recovery codes are bcrypt hashes at the
// production cost, ten of them, and were compared first: every ordinary
// sign-in paid for ten bcrypt comparisons before its code was looked at, and
// on a loaded host -- or under the race detector, where it took 6 s idle and
// over 30 s at six times oversubscription -- the code could pass out of its
// one-step window while it waited, and be refused. The two cannot be confused
// (a TOTP code is six digits, a recovery code is not), so the order changes
// nothing else.
func (m *Manager) acceptCode(user *gateonv1.User, plainSecret, recoveryCodes, code string) (bool, error) {
	if ok, _ := totp.ValidateCustom(code, plainSecret, m.now().UTC(), totpOpts); ok {
		return true, m.completeEnrolment(user, recoveryCodes)
	}
	// Recovery codes are only valid once 2FA is fully enabled, never during the
	// enrollment verification step.
	return m.spendRecoveryCode(user, recoveryCodes, code)
}

// SetClock replaces the clock a TOTP code is checked against. For tests, which
// generate a code for an instant and need it checked at that instant however
// long the host takes to get there.
func (m *Manager) SetClock(now func() time.Time) { m.now = now }

// spendRecoveryCode reports whether code is one of user's unused recovery
// codes, stored as the comma-joined hashes recoveryCodes, and if it is, removes
// it so it cannot be used again. Only an enrolled account has recovery codes
// that count. user.TwoFactorSecret is the stored, encrypted secret.
func (m *Manager) spendRecoveryCode(user *gateonv1.User, recoveryCodes, code string) (bool, error) {
	if !user.TwoFactorEnabled || recoveryCodes == "" {
		return false, nil
	}
	hashes := strings.Split(recoveryCodes, ",")
	i := -1
	if err := m.withHashSlot(func() error {
		i = matchRecoveryCode(hashes, code)
		return nil
	}); err != nil {
		return false, err
	}
	if i < 0 {
		return false, nil
	}
	q := m.dialect.Rebind(QueryUpdate2FA)
	if _, err := m.db.Exec(q, true, user.TwoFactorSecret, strings.Join(removeAt(hashes, i), ","), user.Id); err != nil {
		return false, err
	}
	return true, nil
}

// completeEnrolment turns 2FA on for an account verifying its first code, and
// clears an administrator's pending mandate so the next sign-in goes straight
// to the code. An account already enrolled is left as it is.
// user.TwoFactorSecret is the stored, encrypted secret.
func (m *Manager) completeEnrolment(user *gateonv1.User, recoveryCodes string) error {
	if user.TwoFactorEnabled {
		return nil
	}
	q := m.dialect.Rebind(QueryUpdate2FA)
	if _, err := m.db.Exec(q, true, user.TwoFactorSecret, recoveryCodes, user.Id); err != nil {
		return err
	}
	if user.TwoFactorPending {
		return m.setTwoFactorPending(user.Id, false)
	}
	return nil
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
