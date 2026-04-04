package proxy

import (
	"context"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type mockServiceStore struct {
	config.ServiceStore
	svc *gateonv1.Service
}

func (m *mockServiceStore) Get(ctx context.Context, id string) (*gateonv1.Service, bool) {
	return m.svc, true
}

func TestProxyHandlerBuilder_HealthCheckDefault(t *testing.T) {
	rt := &gateonv1.Route{Id: "test", ServiceId: "test"}

	t.Run("default to gRPC for h2c", func(t *testing.T) {
		svc := &gateonv1.Service{
			Id: "test",
			WeightedTargets: []*gateonv1.Target{
				{Url: "h2c://backend:50051"},
			},
		}
		store := &mockServiceStore{svc: svc}
		b := NewProxyHandlerBuilder(rt, store, nil)
		ph := b.Build()
		defer ph.Close()

		if ph.healthCheckType != gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_GRPC {
			t.Errorf("expected healthCheckType to be GRPC for h2c target, got %v", ph.healthCheckType)
		}
	})

	t.Run("default to HTTP for http", func(t *testing.T) {
		svc := &gateonv1.Service{
			Id: "test",
			WeightedTargets: []*gateonv1.Target{
				{Url: "http://backend:8080"},
			},
		}
		store := &mockServiceStore{svc: svc}
		b := NewProxyHandlerBuilder(rt, store, nil)
		ph := b.Build()
		defer ph.Close()

		if ph.healthCheckType != gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP {
			t.Errorf("expected healthCheckType to be HTTP for http target, got %v", ph.healthCheckType)
		}
	})

	t.Run("explicit HTTP for h2c", func(t *testing.T) {
		svc := &gateonv1.Service{
			Id: "test",
			WeightedTargets: []*gateonv1.Target{
				{Url: "h2c://backend:50051"},
			},
			HealthCheckType: gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP,
			HealthCheckPath: "/health",
		}
		store := &mockServiceStore{svc: svc}
		b := NewProxyHandlerBuilder(rt, store, nil)
		ph := b.Build()
		defer ph.Close()

		if ph.healthCheckType != gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP {
			t.Errorf("expected healthCheckType to be HTTP, got %v", ph.healthCheckType)
		}
	})

	t.Run("default to TCP for raw host:port target", func(t *testing.T) {
		svc := &gateonv1.Service{
			Id: "test",
			WeightedTargets: []*gateonv1.Target{
				{Url: "127.0.0.1:9000"},
			},
		}
		store := &mockServiceStore{svc: svc}
		b := NewProxyHandlerBuilder(rt, store, nil)
		ph := b.Build()
		defer ph.Close()

		if ph.healthCheckType != gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP {
			t.Errorf("expected healthCheckType to be TCP for raw host:port target, got %v", ph.healthCheckType)
		}
	})
}
