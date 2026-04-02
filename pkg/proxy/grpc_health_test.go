package proxy

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func TestCheckGRPCHealth(t *testing.T) {
	// 1. Setup gRPC health server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	healthSrv := health.NewServer()
	grpc_health_v1.RegisterHealthServer(s, healthSrv)

	go s.Serve(lis)
	defer s.Stop()

	targetAddr := lis.Addr().String()

	h := &ProxyHandler{
		healthCheckPath: "", // default service
	}

	// 2. Test healthy
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	if !h.checkGRPCHealth(context.Background(), "h2c://"+targetAddr) {
		t.Error("expected gRPC health to be healthy")
	}

	// 3. Test unhealthy
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	if h.checkGRPCHealth(context.Background(), "h2c://"+targetAddr) {
		t.Error("expected gRPC health to be unhealthy")
	}

	// 4. Test with service name
	h.healthCheckPath = "my-service"
	healthSrv.SetServingStatus("my-service", grpc_health_v1.HealthCheckResponse_SERVING)
	if !h.checkGRPCHealth(context.Background(), "h2c://"+targetAddr) {
		t.Error("expected gRPC health for my-service to be healthy")
	}
}
