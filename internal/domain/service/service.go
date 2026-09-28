// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package service

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Service encapsulates service business logic: validation, ID generation, persistence, proxy invalidation.
type Service interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Service, int32)
	GetService(ctx context.Context, id string) (*gateonv1.Service, bool)
	SaveService(ctx context.Context, svc *gateonv1.Service) error
	DeleteService(ctx context.Context, id string) error
}

// SaveGuard authorizes a service save that would repoint the backend of a route
// carrying a credential-injecting middleware. It runs inside SaveService so
// every transport is held to the same rule (ADR 0038); a nil guard is
// unrestricted.
type SaveGuard interface {
	AuthorizeServiceSave(ctx context.Context, updated *gateonv1.Service) error
}
