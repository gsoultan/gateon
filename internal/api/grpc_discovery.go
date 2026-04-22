package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
)

func (s *ApiService) DiscoverGrpcServices(ctx context.Context, req *gateonv1.DiscoverGrpcServicesRequest) (*gateonv1.DiscoverGrpcServicesResponse, error) {
	if req == nil {
		return nil, errors.New("request is required")
	}
	if req.Url == "" {
		return nil, errors.New("url is required")
	}

	host := req.Url
	useTLS := false
	if h, ok := strings.CutPrefix(req.Url, "h2c://"); ok {
		host = h
	} else if h, ok := strings.CutPrefix(req.Url, "h2://"); ok {
		host = h
		useTLS = true
	} else if h, ok := strings.CutPrefix(req.Url, "h3://"); ok {
		host = h
		useTLS = true
	}

	// SSRF prevention: validate host
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return nil, errors.New("access to localhost is forbidden")
	}

	var opts []grpc.DialOption
	if useTLS {
		tlsCfg, err := gtls.CreateTLSClientConfig(req.TlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create tls config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, host, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", host, err)
	}
	defer conn.Close()

	client := grpc_reflection_v1alpha.NewServerReflectionClient(conn)
	stream, err := client.ServerReflectionInfo(dialCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create reflection stream: %w", err)
	}

	if err := stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{
			ListServices: "*",
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to send reflection request: %w", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive reflection response: %w", err)
	}

	listResp := resp.GetListServicesResponse()
	if listResp == nil {
		return nil, errors.New("no services found")
	}

	var services []string
	for _, svc := range listResp.Service {
		// Filter out standard reflection and health check services if desired
		if svc.Name != "grpc.reflection.v1alpha.ServerReflection" &&
			svc.Name != "grpc.reflection.v1.ServerReflection" &&
			svc.Name != "grpc.health.v1.Health" {
			services = append(services, svc.Name)
		}
	}

	return &gateonv1.DiscoverGrpcServicesResponse{Services: services}, nil
}
