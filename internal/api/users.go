package api

import (
	"context"
	"fmt"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *ApiService) ListUsers(ctx context.Context, req *gateonv1.ListUsersRequest) (*gateonv1.ListUsersResponse, error) {
	if req == nil {
		return &gateonv1.ListUsersResponse{}, nil
	}
	if s.Auth == nil {
		return &gateonv1.ListUsersResponse{}, nil
	}
	if err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	users, totalCount, err := s.Auth.ListUsers(req.Page, req.PageSize, req.Search)
	if err != nil {
		return nil, err
	}
	return &gateonv1.ListUsersResponse{
		Users:      users,
		TotalCount: totalCount,
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

func (s *ApiService) UpdateUser(ctx context.Context, req *gateonv1.UpdateUserRequest) (*gateonv1.UpdateUserResponse, error) {
	if s.Auth == nil || req == nil || req.User == nil {
		return &gateonv1.UpdateUserResponse{Success: false}, nil
	}
	if err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if err := s.Auth.UpsertUser(req.User); err != nil {
		return &gateonv1.UpdateUserResponse{Success: false}, err
	}
	// UpsertUser only covers username/password/role; the disabled and
	// admin-mandated-2FA flags are persisted via dedicated setters. UpsertUser
	// populates req.User.Id when creating a new account.
	if err := s.Auth.SetUserDisabled(req.User.Id, req.User.Disabled); err != nil {
		return &gateonv1.UpdateUserResponse{Success: false}, err
	}
	// Only (re)assert a pending-2FA requirement; never clear an active enrollment.
	// Clearing happens automatically once the user finishes enrollment, and a user
	// who already has 2FA enabled must not be flipped back to "pending".
	if !req.User.TwoFactorEnabled {
		if err := s.Auth.SetTwoFactorPending(req.User.Id, req.User.TwoFactorPending); err != nil {
			return &gateonv1.UpdateUserResponse{Success: false}, err
		}
	}
	s.logAudit(ctx, "update", "user", fmt.Sprintf("Updated user %s (%s)", req.User.Id, req.User.Username))
	return &gateonv1.UpdateUserResponse{Success: true}, nil
}

func (s *ApiService) DeleteUser(ctx context.Context, req *gateonv1.DeleteUserRequest) (*gateonv1.DeleteUserResponse, error) {
	if s.Auth == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteUserResponse{Success: false}, nil
	}
	if err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if err := s.Auth.DeleteUser(req.Id); err != nil {
		return &gateonv1.DeleteUserResponse{Success: false}, err
	}
	s.logAudit(ctx, "delete", "user", fmt.Sprintf("Deleted user %s", req.Id))
	return &gateonv1.DeleteUserResponse{Success: true}, nil
}

func (s *ApiService) ChangePassword(ctx context.Context, req *gateonv1.ChangePasswordRequest) (*gateonv1.ChangePasswordResponse, error) {
	if s.Auth == nil || req == nil || req.Id == "" || req.Password == "" {
		return &gateonv1.ChangePasswordResponse{Success: false}, nil
	}

	// Security: Verify user identity. Only Admins can change other users' passwords.
	claims, _ := ctx.Value(middleware.UserContextKey).(*auth.Claims)
	if claims != nil && claims.Role != auth.RoleAdmin && claims.ID != req.Id {
		return nil, status.Error(codes.PermissionDenied, "cannot change password for another user")
	}

	if err := s.Auth.ChangePassword(req.Id, req.Password); err != nil {
		return &gateonv1.ChangePasswordResponse{Success: false}, err
	}
	s.logAudit(ctx, "change_password", "user", fmt.Sprintf("Changed password for user %s", req.Id))
	return &gateonv1.ChangePasswordResponse{Success: true}, nil
}

func (s *ApiService) requireAdmin(ctx context.Context) error {
	claims, _ := ctx.Value(middleware.UserContextKey).(*auth.Claims)
	if claims == nil || claims.Role != auth.RoleAdmin {
		return status.Error(codes.PermissionDenied, "admin role required")
	}
	return nil
}
