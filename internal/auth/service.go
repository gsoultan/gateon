package auth

import (
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Service defines the contract for authentication and user management.
// It is implemented by Manager.
type Service interface {
	IsSetupDone() bool
	Authenticate(username, password string) (string, *gateonv1.User, error)
	VerifyToken(token string) (any, error)
	ListUsers(page, pageSize int32, search string) ([]*gateonv1.User, int32, error)
	UpsertUser(u *gateonv1.User) error
	DeleteUser(id string) error
	ChangePassword(id, password string) error
	UpdateSymmetricKey(key string)

	// 2FA methods
	Setup2FA(id string) (string, string, []string, error)
	Verify2FA(id, code string) (bool, string, *gateonv1.User, error)
	Disable2FA(id string) error

	Close() error
}
