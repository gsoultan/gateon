// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"
	"github.com/gsoultan/gateon/internal/domain/service"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) ListServices(ctx context.Context, _ *gateonv1.ListServicesRequest) (*gateonv1.ListServicesResponse, error) {
	if s.Services == nil {
		return &gateonv1.ListServicesResponse{Services: nil}, nil
	}
	return &gateonv1.ListServicesResponse{Services: s.Services.List(ctx)}, nil
}

func (s *ApiService) UpdateService(ctx context.Context, req *gateonv1.UpdateServiceRequest) (*gateonv1.UpdateServiceResponse, error) {
	if s.Services == nil || req == nil || req.Service == nil {
		return &gateonv1.UpdateServiceResponse{Success: false}, nil
	}
	if err := s.Services.Update(ctx, req.Service); err != nil {
		return &gateonv1.UpdateServiceResponse{Success: false}, err
	}
	if s.Invalidator != nil {
		s.Invalidator.InvalidateRoutes(func(r *gateonv1.Route) bool {
			return r.ServiceId == req.Service.Id
		})
	}
	s.logAudit(ctx, "update", "service", fmt.Sprintf("Updated service %s", req.Service.Id))
	return &gateonv1.UpdateServiceResponse{Success: true}, nil
}

func (s *ApiService) DeleteService(ctx context.Context, req *gateonv1.DeleteServiceRequest) (*gateonv1.DeleteServiceResponse, error) {
	if s.Services == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteServiceResponse{Success: false}, nil
	}
	// Clear the service id from every route naming it, using the same helper the
	// REST path does. Deleting a service is reachable from two transports; when
	// each maintained its own copy of the cascade, only one of them cleared the
	// references and the persisted state depended on how the caller arrived.
	if s.Routes != nil {
		service.ClearRouteReferences(ctx, s.Routes, req.Id)
	}
	if err := s.Services.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteServiceResponse{Success: false}, err
	}
	if s.Invalidator != nil {
		s.Invalidator.InvalidateRoutes(func(r *gateonv1.Route) bool {
			return r.ServiceId == req.Id
		})
	}
	s.logAudit(ctx, "delete", "service", fmt.Sprintf("Deleted service %s", req.Id))
	return &gateonv1.DeleteServiceResponse{Success: true}, nil
}
