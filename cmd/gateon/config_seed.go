// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package main

import (
	"context"
	"fmt"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const (
	routesFileEnv      = "ROUTES_FILE"
	servicesFileEnv    = "SERVICES_FILE"
	entryPointsFileEnv = "ENTRYPOINTS_FILE"
	middlewaresFileEnv = "MIDDLEWARES_FILE"
	tlsOptionsFileEnv  = "TLS_OPTIONS_FILE"

	routesFileDefault      = "routes.json"
	servicesFileDefault    = "services.json"
	entryPointsFileDefault = "entrypoints.json"
	middlewaresFileDefault = "middlewares.json"
	tlsOptionsFileDefault  = "tls_options.json"
)

// dbConfigStores groups the database-backed configuration registries that may
// need to be seeded from the operator's file-based configuration.
type dbConfigStores struct {
	routes      config.RouteStore
	services    config.ServiceStore
	entryPoints config.EntryPointStore
	middlewares config.MiddlewareStore
	tlsOptions  config.TLSOptionStore
}

// listUpdater is the minimal contract required to copy configuration entries
// from a file-backed registry into a database-backed one.
type listUpdater[T any] interface {
	List(ctx context.Context) []T
	Update(ctx context.Context, item T) error
}

// seedConfigFromFiles imports file-based configuration into empty
// database-backed stores. Without it the JSON/YAML files supplied by the
// operator are silently ignored as soon as a management database exists,
// leaving a fresh installation with no entrypoints, routes or services.
// Stores that already contain entries are never touched, so the import only
// happens once, on a fresh database.
func seedConfigFromFiles(ctx context.Context, dst dbConfigStores) {
	seedStore(ctx, dst.entryPoints, func() listUpdater[*gateonv1.EntryPoint] {
		return config.NewEntryPointRegistry(getEnvDefault(entryPointsFileEnv, entryPointsFileDefault))
	})
	seedStore(ctx, dst.services, func() listUpdater[*gateonv1.Service] {
		return config.NewServiceRegistry(getEnvDefault(servicesFileEnv, servicesFileDefault))
	})
	seedStore(ctx, dst.middlewares, func() listUpdater[*gateonv1.Middleware] {
		return config.NewMiddlewareRegistry(getEnvDefault(middlewaresFileEnv, middlewaresFileDefault))
	})
	seedStore(ctx, dst.tlsOptions, func() listUpdater[*gateonv1.TLSOption] {
		return config.NewTLSOptionRegistry(getEnvDefault(tlsOptionsFileEnv, tlsOptionsFileDefault))
	})
	seedStore(ctx, dst.routes, func() listUpdater[*gateonv1.Route] {
		return config.NewRouteRegistry(getEnvDefault(routesFileEnv, routesFileDefault))
	})
}

// seedStore copies every entry of the file-backed registry produced by src
// into dst, but only when dst is still empty.
func seedStore[T any](ctx context.Context, dst listUpdater[T], src func() listUpdater[T]) {
	if dst == nil || len(dst.List(ctx)) > 0 {
		return
	}

	items := src().List(ctx)
	if len(items) == 0 {
		return
	}

	seeded := 0
	for _, item := range items {
		if err := dst.Update(ctx, item); err != nil {
			logger.L.LogError("failed to seed configuration entry from file",
				"kind", fmt.Sprintf("%T", item), "error", err)
			continue
		}
		seeded++
	}

	logger.L.LogInfo("seeded configuration from file into database",
		"kind", fmt.Sprintf("%T", items[0]), "count", seeded)
}
