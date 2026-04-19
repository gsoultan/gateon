package handlers

import (
	"context"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// GlobalAndAuthAPI defines the API surface needed by global and auth REST handlers.
// Implementations (e.g. *api.ApiService) provide global config and auth operations.
// Use this interface for testability via mock injection.
type GlobalAndAuthAPI interface {
	GetGlobals() config.GlobalConfigStore
	GetTLSManager() tls.TLSManager
	IsSetupRequired(ctx context.Context, req *gateonv1.IsSetupRequiredRequest) (*gateonv1.IsSetupRequiredResponse, error)
	Setup(ctx context.Context, req *gateonv1.SetupRequest) (*gateonv1.SetupResponse, error)
	Login(ctx context.Context, req *gateonv1.LoginRequest) (*gateonv1.LoginResponse, error)
	ListUsers(ctx context.Context, req *gateonv1.ListUsersRequest) (*gateonv1.ListUsersResponse, error)
	UpdateUser(ctx context.Context, req *gateonv1.UpdateUserRequest) (*gateonv1.UpdateUserResponse, error)
	DeleteUser(ctx context.Context, req *gateonv1.DeleteUserRequest) (*gateonv1.DeleteUserResponse, error)
	ChangePassword(ctx context.Context, req *gateonv1.ChangePasswordRequest) (*gateonv1.ChangePasswordResponse, error)
}
