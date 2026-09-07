// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/security/secretmask"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

func (s *ApiService) ListMiddlewares(ctx context.Context, _ *gateonv1.ListMiddlewaresRequest) (*gateonv1.ListMiddlewaresResponse, error) {
	if s.Middlewares == nil {
		return &gateonv1.ListMiddlewaresResponse{Middlewares: nil}, nil
	}
	return &gateonv1.ListMiddlewaresResponse{
		Middlewares: maskMiddlewares(ctx, s.Middlewares.List(ctx)),
	}, nil
}

// maskMiddlewares hides credentials from a caller who could not change them.
//
// The same rule as the REST handler, applied here because this is the same data
// behind a different transport. Authorization was once enforced on the REST
// routes only while Connect and gRPC served the same methods unguarded; a
// redaction that covered one transport would be that defect again, and the RBAC
// table already lets a viewer call this procedure.
//
// The returned messages are copies: the originals are the live configuration,
// and masking in place would delete the credentials from the running gateway on
// a read.
func maskMiddlewares(ctx context.Context, mws []*gateonv1.Middleware) []*gateonv1.Middleware {
	if canWriteMiddlewares(ctx) {
		return mws
	}
	out := make([]*gateonv1.Middleware, 0, len(mws))
	for _, mw := range mws {
		if mw == nil {
			continue
		}
		// proto.Clone rather than a struct copy: a generated message carries
		// internal state that must not be copied by value, and listing the
		// fields by hand would silently drop any field added to Middleware
		// later -- from the masked response only, which is the half nobody
		// would be looking at.
		clone, ok := proto.Clone(mw).(*gateonv1.Middleware)
		if !ok {
			continue
		}
		clone.Config = secretmask.Config(mw.Config)
		out = append(out, clone)
	}
	return out
}

// canWriteMiddlewares reports whether the caller could set these values anyway,
// in which case showing them reveals nothing they do not already control.
func canWriteMiddlewares(ctx context.Context) bool {
	claimsVal := ctx.Value(middleware.UserContextKey)
	if claimsVal == nil {
		return true // auth disabled, as elsewhere
	}
	claims, ok := claimsVal.(*auth.Claims)
	if !ok || claims == nil {
		return false
	}
	return auth.Allowed(ctx, claims.Role, auth.ActionWrite, auth.ResourceMiddlewares)
}

func (s *ApiService) UpdateMiddleware(ctx context.Context, req *gateonv1.UpdateMiddlewareRequest) (*gateonv1.UpdateMiddlewareResponse, error) {
	if s.Middlewares == nil || req == nil || req.Middleware == nil {
		return &gateonv1.UpdateMiddlewareResponse{Success: false}, nil
	}
	// A caller who was shown placeholders instead of credentials sends them back
	// on any save that did not touch them. Writing the placeholder literally
	// would destroy the secret through an unrelated edit.
	if req.Middleware.Id != "" {
		if prev, ok := s.Middlewares.Get(ctx, req.Middleware.Id); ok && prev != nil {
			req.Middleware.Config = secretmask.Preserve(req.Middleware.Config, prev.Config)
		}
	}
	if err := s.Middlewares.Update(ctx, req.Middleware); err != nil {
		return &gateonv1.UpdateMiddlewareResponse{Success: false}, err
	}
	if s.Invalidator != nil {
		s.Invalidator.InvalidateRoutes(func(r *gateonv1.Route) bool {
			for _, mID := range r.Middlewares {
				if mID == req.Middleware.Id {
					return true
				}
			}
			return false
		})
	}
	s.logAudit(ctx, "update", "middleware", fmt.Sprintf("Updated middleware %s", req.Middleware.Id))
	return &gateonv1.UpdateMiddlewareResponse{Success: true}, nil
}

func (s *ApiService) DeleteMiddleware(ctx context.Context, req *gateonv1.DeleteMiddlewareRequest) (*gateonv1.DeleteMiddlewareResponse, error) {
	if s.Middlewares == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteMiddlewareResponse{Success: false}, nil
	}
	if err := s.Middlewares.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteMiddlewareResponse{Success: false}, err
	}
	if s.Invalidator != nil {
		s.Invalidator.InvalidateRoutes(func(r *gateonv1.Route) bool {
			for _, mID := range r.Middlewares {
				if mID == req.Id {
					return true
				}
			}
			return false
		})
	}
	s.logAudit(ctx, "delete", "middleware", fmt.Sprintf("Deleted middleware %s", req.Id))
	return &gateonv1.DeleteMiddlewareResponse{Success: true}, nil
}
