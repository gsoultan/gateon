// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
)

// SetupTokenFile is the file, in the data directory, that holds the setup token
// while setup is open.
const SetupTokenFile = "setup-token"

// minSetupTokenLen is the shortest GATEON_SETUP_TOKEN accepted.
const minSetupTokenLen = 16

// ErrSetupTokenTooShort refuses a GATEON_SETUP_TOKEN a caller could guess.
var ErrSetupTokenTooShort = fmt.Errorf("GATEON_SETUP_TOKEN must be at least %d characters", minSetupTokenLen)

// ErrSetupTokenRequired answers a first-run request that does not carry the
// token, on every endpoint that requires it.
var ErrSetupTokenRequired = errors.New("a setup token is required: it is printed in the gateway's log at " +
	"startup and saved as " + SetupTokenFile + " in its data directory, or it is the value of GATEON_SETUP_TOKEN")

// SetupToken is the one-time credential first-run setup requires. See ADR 0021.
//
// Setup is served before any account exists, so it cannot ask for a login, and
// with nothing to ask for, whoever reached a fresh gateway first made themselves
// its administrator -- or used its database probe on the network it sits in. The
// token is what the operator has and a passer-by does not: it is printed to the
// gateway's own log and written to its data directory, which only someone with
// the host or the container can read.
type SetupToken struct {
	value   atomic.Pointer[string]
	path    atomic.Pointer[string]
	fromEnv bool
}

// NewSetupToken returns the token setup will require: fromEnv when it is set,
// which is how automation supplies one, otherwise 32 random bytes.
func NewSetupToken(fromEnv string) (*SetupToken, error) {
	t := &SetupToken{fromEnv: fromEnv != ""}
	v := fromEnv
	switch {
	case v == "":
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate setup token: %w", err)
		}
		v = base64.RawURLEncoding.EncodeToString(b)
	case len(v) < minSetupTokenLen:
		return nil, ErrSetupTokenTooShort
	}
	t.value.Store(&v)
	return t, nil
}

// Matches reports, in constant time, whether got is the token. A nil or retired
// token matches nothing, so setup stays closed rather than open when a token was
// never wired in.
func (t *SetupToken) Matches(got string) bool {
	want := t.Value()
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// Value is the token itself, for telling the operator; "" once retired.
func (t *SetupToken) Value() string {
	if t == nil {
		return ""
	}
	if v := t.value.Load(); v != nil {
		return *v
	}
	return ""
}

// FromEnv reports whether the operator supplied the token, in which case it is
// neither printed nor written: they already have it.
func (t *SetupToken) FromEnv() bool { return t != nil && t.fromEnv }

// Publish writes the token into dir, readable by the gateway's own account
// only, and returns the path. The file is created afresh -- never through
// whatever is already at that name, which might be a link, or a file with
// looser permissions left by an earlier run.
func (t *SetupToken) Publish(dir string) (string, error) {
	p := filepath.Join(dir, SetupTokenFile)
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(t.Value() + "\n"); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	t.path.Store(&p)
	return p, nil
}

// Retire ends the token once setup has completed: it matches nothing more, and
// the file Publish wrote is removed.
func (t *SetupToken) Retire() {
	if t == nil {
		return
	}
	retired := ""
	t.value.Store(&retired)
	if p := t.path.Load(); p != nil {
		_ = os.Remove(*p)
	}
}
