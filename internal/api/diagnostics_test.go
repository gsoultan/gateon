package api

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/stretchr/testify/assert"
)

func TestGetDiagnostics_Enhanced(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Mock stores
	epStore := config.NewEntryPointRegistry(filepath.Join(tmpDir, "entrypoints.json"))
	routeStore := config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))
	svcStore := config.NewServiceRegistry(filepath.Join(tmpDir, "services.json"))
	mwStore := config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))

	// Setup data
	ep := &gateonv1.EntryPoint{
		Id:      "ep1",
		Name:    "HTTP",
		Address: ":80",
		Type:    gateonv1.EntryPoint_HTTP,
	}
	_ = epStore.Update(ctx, ep)

	svc := &gateonv1.Service{
		Id:   "svc1",
		Name: "MyService",
	}
	_ = svcStore.Update(ctx, svc)

	mw := &gateonv1.Middleware{
		Id:   "mw1",
		Name: "Auth",
		Type: "auth",
	}
	_ = mwStore.Update(ctx, mw)

	rt := &gateonv1.Route{
		Id:          "rt1",
		Name:        "Route1",
		Entrypoints: []string{"ep1"},
		ServiceId:   "svc1",
		Middlewares: []string{"mw1"},
		Rule:        "Path(`/api`)",
	}
	_ = routeStore.Update(ctx, rt)

	apiSvc := NewApiService(ApiServiceConfig{
		EntryPoints: epStore,
		Routes:      routeStore,
		Services:    svcStore,
		Middlewares: mwStore,
		RouteStatsProvider: func(routeID string) []proxy.TargetStats {
			if routeID == "rt1" {
				return []proxy.TargetStats{
					{URL: "http://localhost:8080", Alive: true},
				}
			}
			return nil
		},
	})

	resp, err := apiSvc.GetDiagnostics(ctx, &gateonv1.GetDiagnosticsRequest{})
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	assert.Len(t, resp.Entrypoints, 1)
	diagEP := resp.Entrypoints[0]
	assert.Equal(t, "ep1", diagEP.Id)
	assert.Len(t, diagEP.Routes, 1)

	diagRoute := diagEP.Routes[0]
	assert.Equal(t, "rt1", diagRoute.Id)
	assert.Equal(t, "MyService", diagRoute.ServiceName)
	assert.True(t, diagRoute.ServiceHealthy)
	assert.True(t, diagRoute.Healthy)

	assert.Len(t, diagRoute.Middlewares, 1)
	diagMW := diagRoute.Middlewares[0]
	assert.Equal(t, "mw1", diagMW.Id)
	assert.Equal(t, "Auth", diagMW.Name)
	assert.True(t, diagMW.Healthy)
}

func TestGetDiagnostics_ServiceDown(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	epStore := config.NewEntryPointRegistry(filepath.Join(tmpDir, "entrypoints.json"))
	routeStore := config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))
	svcStore := config.NewServiceRegistry(filepath.Join(tmpDir, "services.json"))
	mwStore := config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))

	_ = epStore.Update(ctx, &gateonv1.EntryPoint{Id: "ep1", Name: "HTTP", Type: gateonv1.EntryPoint_HTTP})
	_ = svcStore.Update(ctx, &gateonv1.Service{Id: "svc1", Name: "MyService"})
	_ = routeStore.Update(ctx, &gateonv1.Route{
		Id: "rt1", Name: "Route1", Entrypoints: []string{"ep1"}, ServiceId: "svc1",
	})

	apiSvc := NewApiService(ApiServiceConfig{
		EntryPoints: epStore,
		Routes:      routeStore,
		Services:    svcStore,
		Middlewares: mwStore,
		RouteStatsProvider: func(routeID string) []proxy.TargetStats {
			return []proxy.TargetStats{
				{URL: "http://localhost:8080", Alive: false},
			}
		},
	})

	resp, _ := apiSvc.GetDiagnostics(ctx, &gateonv1.GetDiagnosticsRequest{})
	diagRoute := resp.Entrypoints[0].Routes[0]
	assert.False(t, diagRoute.ServiceHealthy)
	assert.False(t, diagRoute.Healthy)
	assert.Equal(t, "All backend targets are down", diagRoute.Error)
}
