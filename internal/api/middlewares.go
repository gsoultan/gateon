// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config/mwsecret"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) ListMiddlewares(ctx context.Context, _ *gateonv1.ListMiddlewaresRequest) (*gateonv1.ListMiddlewaresResponse, error) {
	if s.Middlewares == nil {
		return &gateonv1.ListMiddlewaresResponse{Middlewares: nil}, nil
	}
	return &gateonv1.ListMiddlewaresResponse{
		Middlewares: maskMiddlewares(ctx, s.Middlewares.List(ctx)),
	}, nil
}

// maskMiddlewares hides every stored secret from every caller, as the REST
// handler does (ADR 0030): this is the same data behind a different transport,
// and a redaction that covered one transport would be the REST-only
// authorization defect again. The messages returned are copies of the live
// configuration.
func maskMiddlewares(ctx context.Context, mws []*gateonv1.Middleware) []*gateonv1.Middleware {
	return mwsecret.MaskAll(mws, canWriteMiddlewares(ctx))
}

// canWriteMiddlewares reports whether the caller may write middlewares, and so
// reads the values of headers and query parameters whose names give no
// credential away; no caller reads a stored secret.
func canWriteMiddlewares(ctx context.Context) bool {
	claims, present := callerClaims(ctx)
	if !present {
		return true // auth disabled, as elsewhere
	}
	if claims == nil {
		return false
	}
	return auth.Allowed(ctx, claims.Role, auth.ActionWrite, auth.ResourceMiddlewares)
}

func (s *ApiService) UpdateMiddleware(ctx context.Context, req *gateonv1.UpdateMiddlewareRequest) (*gateonv1.UpdateMiddlewareResponse, error) {
	if s.Middlewares == nil || req == nil || req.Middleware == nil {
		return &gateonv1.UpdateMiddlewareResponse{Success: false}, nil
	}
	// Through the domain service, as the REST handler: it keeps every stored
	// secret the caller sent the placeholder back for (ADR 0030), the factory proves the
	// config can be built before anything is written, an id is assigned, and a
	// WAF policy drops the WAF cache. Written to the store directly, a config
	// the factory cannot build was persisted and never failed -- the router
	// skips a middleware whose Create fails, so the route ran without it. See
	// domain_services.go.
	if err := s.middlewareService().SaveMiddleware(ctx, req.Middleware); err != nil {
		return &gateonv1.UpdateMiddlewareResponse{Success: false}, err
	}
	s.logAudit(ctx, "update", "middleware", fmt.Sprintf("Updated middleware %s", req.Middleware.Id))
	return &gateonv1.UpdateMiddlewareResponse{Success: true}, nil
}

func (s *ApiService) DeleteMiddleware(ctx context.Context, req *gateonv1.DeleteMiddlewareRequest) (*gateonv1.DeleteMiddlewareResponse, error) {
	if s.Middlewares == nil || s.Routes == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteMiddlewareResponse{Success: false}, nil
	}
	// Through the domain service, as the REST handler: it unlinks the middleware
	// from every route naming it and refuses to delete while one still does.
	// Deleting the record directly left those routes pointing at an id the
	// router silently skips -- a route given a WAF or an auth middleware lost it
	// and the RPC reported success.
	if err := s.middlewareService().DeleteMiddleware(ctx, req.Id); err != nil {
		return &gateonv1.DeleteMiddlewareResponse{Success: false}, err
	}
	s.logAudit(ctx, "delete", "middleware", fmt.Sprintf("Deleted middleware %s", req.Id))
	return &gateonv1.DeleteMiddlewareResponse{Success: true}, nil
}
