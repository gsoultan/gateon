// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"

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
	// Through the domain service, as the REST handler: a service that arrived
	// without an id is given one, where stored directly it sat under "" and
	// neither transport could delete it. See domain_services.go.
	if err := s.serviceService().SaveService(ctx, req.Service); err != nil {
		return &gateonv1.UpdateServiceResponse{Success: false}, err
	}
	s.logAudit(ctx, "update", "service", fmt.Sprintf("Updated service %s", req.Service.Id))
	return &gateonv1.UpdateServiceResponse{Success: true}, nil
}

func (s *ApiService) DeleteService(ctx context.Context, req *gateonv1.DeleteServiceRequest) (*gateonv1.DeleteServiceResponse, error) {
	if s.Services == nil || s.Routes == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteServiceResponse{Success: false}, nil
	}
	// Through the domain service, as the REST handler. This used to clear the
	// service id from every route naming it and then invalidate with the
	// predicate `r.ServiceId == id` -- evaluated against routes that no longer
	// carried the id, so nothing was invalidated and each route's cached proxy
	// kept forwarding to the deleted service's backends. The domain service
	// invalidates the routes it changed, by id.
	if err := s.serviceService().DeleteService(ctx, req.Id); err != nil {
		return &gateonv1.DeleteServiceResponse{Success: false}, err
	}
	s.logAudit(ctx, "delete", "service", fmt.Sprintf("Deleted service %s", req.Id))
	return &gateonv1.DeleteServiceResponse{Success: true}, nil
}
