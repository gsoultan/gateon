package config

import (
	"context"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

// ConfigVisitor visits config entities for export, validation, or audit.
// Implements Visitor pattern for config operations without coupling.
type ConfigVisitor interface {
	VisitRoute(rt *gateonv1.Route) error
	VisitService(svc *gateonv1.Service) error
	VisitEntryPoint(ep *gateonv1.EntryPoint) error
	VisitMiddleware(mw *gateonv1.Middleware) error
}

// AcceptRoutes calls visitor.VisitRoute for each route.
func AcceptRoutes(ctx context.Context, store RouteStore, visitor ConfigVisitor) error {
	for _, rt := range store.List(ctx) {
		if err := visitor.VisitRoute(rt); err != nil {
			return err
		}
	}
	return nil
}

// AcceptServices calls visitor.VisitService for each service.
func AcceptServices(ctx context.Context, store ServiceStore, visitor ConfigVisitor) error {
	for _, svc := range store.List(ctx) {
		if err := visitor.VisitService(svc); err != nil {
			return err
		}
	}
	return nil
}

// AcceptEntryPoints calls visitor.VisitEntryPoint for each entrypoint.
func AcceptEntryPoints(ctx context.Context, store EntryPointStore, visitor ConfigVisitor) error {
	for _, ep := range store.List(ctx) {
		if err := visitor.VisitEntryPoint(ep); err != nil {
			return err
		}
	}
	return nil
}

// AcceptMiddlewares calls visitor.VisitMiddleware for each middleware.
func AcceptMiddlewares(ctx context.Context, store MiddlewareStore, visitor ConfigVisitor) error {
	for _, mw := range store.List(ctx) {
		if err := visitor.VisitMiddleware(mw); err != nil {
			return err
		}
	}
	return nil
}
