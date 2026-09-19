// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) ListEntryPoints(ctx context.Context, _ *gateonv1.ListEntryPointsRequest) (*gateonv1.ListEntryPointsResponse, error) {
	if s.EntryPoints == nil {
		return &gateonv1.ListEntryPointsResponse{EntryPoints: nil}, nil
	}
	return &gateonv1.ListEntryPointsResponse{EntryPoints: s.EntryPoints.List(ctx)}, nil
}

func (s *ApiService) UpdateEntryPoint(ctx context.Context, req *gateonv1.UpdateEntryPointRequest) (*gateonv1.UpdateEntryPointResponse, error) {
	if s.EntryPoints == nil || req == nil || req.EntryPoint == nil {
		return &gateonv1.UpdateEntryPointResponse{Success: false}, nil
	}
	// Through the domain service, as the REST handler: an entrypoint needs an
	// address -- stored without one, every runner returns on `addr == ""`
	// without logging, so it is listed and bindable and never listens -- is
	// given an id, has its type inferred from its protocols, and invalidates the
	// routes and TLS state it affects. See domain_services.go.
	if err := s.entryPointService().SaveEntryPoint(ctx, req.EntryPoint); err != nil {
		return &gateonv1.UpdateEntryPointResponse{Success: false}, err
	}
	s.logAudit(ctx, "update", "entrypoint", fmt.Sprintf("Updated entrypoint %s", req.EntryPoint.Id))
	return &gateonv1.UpdateEntryPointResponse{Success: true}, nil
}

func (s *ApiService) DeleteEntryPoint(ctx context.Context, req *gateonv1.DeleteEntryPointRequest) (*gateonv1.DeleteEntryPointResponse, error) {
	if s.EntryPoints == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteEntryPointResponse{Success: false}, nil
	}
	if err := s.EntryPoints.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteEntryPointResponse{Success: false}, err
	}
	if s.Invalidator != nil {
		s.Invalidator.InvalidateRoutes(func(r *gateonv1.Route) bool {
			for _, epID := range r.Entrypoints {
				if epID == req.Id {
					return true
				}
			}
			return false
		})
		s.Invalidator.InvalidateTLS()
	}
	s.logAudit(ctx, "delete", "entrypoint", fmt.Sprintf("Deleted entrypoint %s", req.Id))
	return &gateonv1.DeleteEntryPointResponse{Success: true}, nil
}
