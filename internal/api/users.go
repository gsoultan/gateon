// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/auth/apitoken"
	"github.com/gsoultan/gateon/internal/auth/passpolicy"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *ApiService) ListUsers(ctx context.Context, req *gateonv1.ListUsersRequest) (*gateonv1.ListUsersResponse, error) {
	if req == nil {
		return &gateonv1.ListUsersResponse{}, nil
	}
	if !auth.Available(s.Auth) {
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
	if !auth.Available(s.Auth) || req == nil || req.User == nil {
		return &gateonv1.UpdateUserResponse{Success: false}, nil
	}
	if err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	// A password here is a credential change, and for the caller's own account
	// it goes through ChangePassword, which asks for the current one. Without
	// this, the session alone could set an administrator's password by editing
	// the administrator as a user.
	if req.User.GetPassword() != "" && s.updatesOwnAccount(ctx, req.User) {
		return nil, status.Error(codes.PermissionDenied,
			"change your own password with the password change, which asks for your current password")
	}
	if err := s.Auth.UpsertUser(req.User); err != nil {
		// A refusal, not a failure: the name belongs to another account and
		// nothing was written. AlreadyExists is 409 over REST.
		if errors.Is(err, auth.ErrUsernameTaken) {
			return nil, status.Error(codes.AlreadyExists, auth.ErrUsernameTaken.Error())
		}
		// A refusal too: the password policy (ADR 0050), named, 400 over REST.
		if errors.Is(err, passpolicy.ErrWeak) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
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

// updatesOwnAccount reports whether an update of u lands on the caller's own
// account. UpsertUser writes an existing account by its id and nothing else:
// a request with another id and the caller's username is a create, which the
// taken username refuses. So the id decides. (It used to write by username,
// and this looked the username up as well, to catch a fresh id carrying the
// caller's name onto the caller's account.)
func (s *ApiService) updatesOwnAccount(ctx context.Context, u *gateonv1.User) bool {
	claims, _ := callerClaims(ctx)
	return claims != nil && u.GetId() == claims.ID
}

func (s *ApiService) DeleteUser(ctx context.Context, req *gateonv1.DeleteUserRequest) (*gateonv1.DeleteUserResponse, error) {
	if !auth.Available(s.Auth) || req == nil || req.Id == "" {
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
	if !auth.Available(s.Auth) || req == nil || req.Id == "" || req.Password == "" {
		return &gateonv1.ChangePasswordResponse{Success: false}, nil
	}

	// Security: Verify user identity. Only Admins can change other users' passwords.
	//
	// This used to read the context key with a discarded ok and then test
	// `claims != nil && ...`, so a claims value that could not be asserted left
	// claims nil, made the whole condition false, and fell through to change
	// the password for whatever id the request named -- the check skipped by
	// exactly the caller it could not identify. requireAdmin, ten lines below,
	// denies on that same condition.
	//
	// And no caller at all is refused too. "No claims" used to mean "auth is
	// off, anything goes", so with authentication switched off -- or on any
	// path that reached here without a credential -- an anonymous request reset
	// the administrator's password by id (M3, ADR 0050). A password change acts
	// for an authenticated caller or not at all, whatever the transport and
	// whatever the deployment's authentication setting.
	claims, present := callerClaims(ctx)
	if !present || claims == nil || (claims.Role != auth.RoleAdmin && claims.ID != req.Id) {
		return nil, status.Error(codes.PermissionDenied, "cannot change password for another user")
	}

	// Your own password needs the one you have now: see auth.Manager.ChangeOwnPassword.
	// An administrator resetting another account keeps today's rule.
	if claims.ID == req.Id {
		if err := s.changeOwnPassword(ctx, req); err != nil {
			return nil, err
		}
	} else if err := s.Auth.ChangePassword(req.Id, req.Password); err != nil {
		if errors.Is(err, passpolicy.ErrWeak) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return &gateonv1.ChangePasswordResponse{Success: false}, err
	}
	s.logAudit(ctx, "change_password", "user", fmt.Sprintf("Changed password for user %s", req.Id))
	return &gateonv1.ChangePasswordResponse{Success: true}, nil
}

// changeOwnPassword changes the caller's own password once they have shown
// the current one, and answers a refusal with the status every transport
// carries: InvalidArgument for a missing password (not counted -- it is not a
// guess), PermissionDenied for a wrong one, ResourceExhausted for a locked
// account. Never Unauthenticated: the caller's session is fine, and the
// dashboard signs the user out on the 401 that would become.
func (s *ApiService) changeOwnPassword(ctx context.Context, req *gateonv1.ChangePasswordRequest) error {
	if req.GetCurrentPassword() == "" {
		return status.Error(codes.InvalidArgument, "your current password is required to change it")
	}
	err := s.Auth.ChangeOwnPassword(req.Id, req.GetCurrentPassword(), req.Password)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, passpolicy.ErrWeak):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, auth.ErrInvalidCredentials):
		s.logAudit(ctx, "change_password_refused", "user", fmt.Sprintf("Wrong current password for user %s", req.Id))
		return status.Error(codes.PermissionDenied, "the current password is incorrect")
	case errors.Is(err, auth.ErrAccountLocked):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, auth.ErrAccountDisabled):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		logger.L.LogError("password change failed", "error", err, "user", req.Id)
		return status.Error(codes.Internal, "the password could not be changed")
	}
}

func (s *ApiService) requireAdmin(ctx context.Context) error {
	claims, _ := callerClaims(ctx)
	if claims == nil || claims.Role != auth.RoleAdmin {
		return status.Error(codes.PermissionDenied, "admin role required")
	}
	return nil
}

// errNoTokenStore answers the token RPCs before there is a database.
var errNoTokenStore = status.Error(codes.Unavailable, "api tokens are unavailable until setup has run")

// tokenStore is the scrape-credential store, for an administrator only.
func (s *ApiService) tokenStore(ctx context.Context) (*apitoken.Store, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if !auth.Available(s.Auth) || s.Auth.APITokens() == nil {
		return nil, errNoTokenStore
	}
	return s.Auth.APITokens(), nil
}

// ListApiTokens lists the scrape credentials, without their secrets (ADR 0050).
func (s *ApiService) ListApiTokens(ctx context.Context, req *gateonv1.ListApiTokensRequest) (*gateonv1.ListApiTokensResponse, error) {
	store, err := s.tokenStore(ctx)
	if err != nil {
		return nil, err
	}
	tokens, total, err := store.List(ctx, int(req.GetPage()), int(req.GetPageSize()))
	if err != nil {
		return nil, err
	}
	out := &gateonv1.ListApiTokensResponse{
		TotalCount: int32(total), //nolint:gosec // at most apitoken.MaxActive
		Page:       req.GetPage(),
		PageSize:   req.GetPageSize(),
	}
	for _, t := range tokens {
		out.Tokens = append(out.Tokens, apiTokenProto(t))
	}
	return out, nil
}

// CreateApiToken issues a scrape credential and returns its secret, once.
func (s *ApiService) CreateApiToken(ctx context.Context, req *gateonv1.CreateApiTokenRequest) (*gateonv1.CreateApiTokenResponse, error) {
	store, err := s.tokenStore(ctx)
	if err != nil {
		return nil, err
	}
	claims, _ := callerClaims(ctx)
	tok, secret, err := store.Create(ctx, apitoken.CreateParams{
		Name: req.GetName(), Scopes: req.GetScopes(), CreatedBy: claims.Username, TTLDays: int(req.GetTtlDays()),
	})
	switch {
	case errors.Is(err, apitoken.ErrBadRequest):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, apitoken.ErrTooMany):
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	case err != nil:
		return nil, err
	}
	s.logAudit(ctx, "create", "api_token", fmt.Sprintf("Created API token %s (%s) with scopes %v", tok.ID, tok.Name, tok.Scopes))
	return &gateonv1.CreateApiTokenResponse{Token: apiTokenProto(tok), Secret: secret}, nil
}

// RevokeApiToken deletes a scrape credential; it stops working at once.
func (s *ApiService) RevokeApiToken(ctx context.Context, req *gateonv1.RevokeApiTokenRequest) (*gateonv1.RevokeApiTokenResponse, error) {
	store, err := s.tokenStore(ctx)
	if err != nil {
		return nil, err
	}
	if err := store.Revoke(ctx, req.GetId()); err != nil {
		if errors.Is(err, apitoken.ErrNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, err
	}
	s.logAudit(ctx, "revoke", "api_token", "Revoked API token "+req.GetId())
	return &gateonv1.RevokeApiTokenResponse{Success: true}, nil
}

func apiTokenProto(t apitoken.Token) *gateonv1.ApiToken {
	out := &gateonv1.ApiToken{
		Id: t.ID, Name: t.Name, Hint: t.Hint, CreatedBy: t.CreatedBy,
		CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339),
	}
	for _, sc := range t.Scopes {
		out.Scopes = append(out.Scopes, string(sc))
	}
	if !t.LastUsedAt.IsZero() {
		out.LastUsedAt = t.LastUsedAt.UTC().Format(time.RFC3339)
	}
	if !t.ExpiresAt.IsZero() {
		out.ExpiresAt = t.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return out
}
