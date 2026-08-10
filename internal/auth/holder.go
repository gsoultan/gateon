// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package auth

import (
	"errors"
	"sync/atomic"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ErrUnavailable is returned by a Holder that has no backing Service yet. It
// means "authentication cannot be performed", never "authentication passed" —
// every caller must treat it as a denial.
var ErrUnavailable = errors.New("auth service is not available")

// Holder is a swappable Service reference.
//
// On a first run there is no global.json, so no auth Manager can be built at
// startup (see internal/inits). Setup creates one later, in the middle of the
// process lifetime. Before this type existed, the manager built by Setup was
// only ever published to ApiService: the HTTP base handler had captured the
// startup value — nil — by value, and kept serving the whole management API
// with no authentication until someone restarted the gateway. A fresh install
// left on a routable address was therefore claimable by whoever reached it
// first, and stayed open even after an administrator had been created.
//
// Holder closes that window. It is installed once at startup, handed to every
// consumer, and swapped atomically when Setup produces a real Manager. It is
// safe for concurrent use: Set may run while requests are reading.
type Holder struct {
	svc atomic.Pointer[Service]
}

// NewHolder returns a Holder wrapping initial, which may be nil.
func NewHolder(initial Service) *Holder {
	h := &Holder{}
	h.Set(initial)
	return h
}

// Set swaps the backing service. Passing nil makes the Holder unavailable
// again, which fails closed rather than open.
func (h *Holder) Set(s Service) {
	if s == nil {
		h.svc.Store(nil)
		return
	}
	h.svc.Store(&s)
}

// Get returns the backing service, or nil when none is installed.
func (h *Holder) Get() Service {
	p := h.svc.Load()
	if p == nil {
		return nil
	}
	return *p
}

// Ready reports whether a backing service is installed.
func (h *Holder) Ready() bool { return h.Get() != nil }

// Available reports whether s can actually authenticate a request. It is the
// replacement for `x == nil` at call sites that hold a Service: a Holder is
// never nil but is not usable until Setup has run, and a plain nil interface
// is not usable either. Both must deny.
func Available(s Service) bool {
	if s == nil {
		return false
	}
	if h, ok := s.(*Holder); ok {
		return h.Ready()
	}
	return true
}

func (h *Holder) IsSetupDone() bool {
	s := h.Get()
	if s == nil {
		return false
	}
	return s.IsSetupDone()
}

func (h *Holder) Authenticate(username, password string) (string, *gateonv1.User, error) {
	s := h.Get()
	if s == nil {
		return "", nil, ErrUnavailable
	}
	return s.Authenticate(username, password)
}

// VerifyToken denies every token while no backing service exists. This is the
// single most important method on the type: returning a nil error here would
// admit an unauthenticated request as an authenticated one.
func (h *Holder) VerifyToken(token string) (any, error) {
	s := h.Get()
	if s == nil {
		return nil, ErrUnavailable
	}
	return s.VerifyToken(token)
}

func (h *Holder) ListUsers(page, pageSize int32, search string) ([]*gateonv1.User, int32, error) {
	s := h.Get()
	if s == nil {
		return nil, 0, ErrUnavailable
	}
	return s.ListUsers(page, pageSize, search)
}

func (h *Holder) UpsertUser(u *gateonv1.User) error {
	s := h.Get()
	if s == nil {
		return ErrUnavailable
	}
	return s.UpsertUser(u)
}

func (h *Holder) DeleteUser(id string) error {
	s := h.Get()
	if s == nil {
		return ErrUnavailable
	}
	return s.DeleteUser(id)
}

func (h *Holder) ChangePassword(id, password string) error {
	s := h.Get()
	if s == nil {
		return ErrUnavailable
	}
	return s.ChangePassword(id, password)
}

func (h *Holder) UpdateSymmetricKey(key string) {
	if s := h.Get(); s != nil {
		s.UpdateSymmetricKey(key)
	}
}

func (h *Holder) SetUserDisabled(id string, disabled bool) error {
	s := h.Get()
	if s == nil {
		return ErrUnavailable
	}
	return s.SetUserDisabled(id, disabled)
}

func (h *Holder) SetTwoFactorPending(id string, pending bool) error {
	s := h.Get()
	if s == nil {
		return ErrUnavailable
	}
	return s.SetTwoFactorPending(id, pending)
}

func (h *Holder) Setup2FA(id string) (string, string, []string, error) {
	s := h.Get()
	if s == nil {
		return "", "", nil, ErrUnavailable
	}
	return s.Setup2FA(id)
}

func (h *Holder) EnrollPending2FA(username, password string) (string, string, []string, string, error) {
	s := h.Get()
	if s == nil {
		return "", "", nil, "", ErrUnavailable
	}
	return s.EnrollPending2FA(username, password)
}

func (h *Holder) Verify2FA(id, code string) (bool, string, *gateonv1.User, error) {
	s := h.Get()
	if s == nil {
		return false, "", nil, ErrUnavailable
	}
	return s.Verify2FA(id, code)
}

func (h *Holder) Disable2FA(id string) error {
	s := h.Get()
	if s == nil {
		return ErrUnavailable
	}
	return s.Disable2FA(id)
}

func (h *Holder) Close() error {
	s := h.Get()
	if s == nil {
		return nil
	}
	return s.Close()
}

var _ Service = (*Holder)(nil)
