// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package route

import (
	"context"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Service encapsulates route business logic: validation, ID generation, persistence, proxy invalidation.
type Service interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string, filter *config.RouteFilter) ([]*gateonv1.Route, int32)
	GetRoute(ctx context.Context, id string) (*gateonv1.Route, bool)
	SaveRoute(ctx context.Context, rt *gateonv1.Route) error
	DeleteRoute(ctx context.Context, id string) error
}

// SaveGuard authorizes a route save that may bind a middleware injecting a
// credential toward the backend. It runs inside SaveRoute so every transport
// -- REST, Connect/gRPC and config-import -- is held to the same rule (ADR
// 0038). A nil guard means no restriction: an internal save, or a build wired
// before the guard exists.
type SaveGuard interface {
	AuthorizeRouteSave(ctx context.Context, updated *gateonv1.Route) error
}
