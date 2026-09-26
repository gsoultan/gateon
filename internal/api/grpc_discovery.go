// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/gsoultan/gateon/internal/discovery"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	reflectionv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
)

// refuseBlockedGrpcAddress is the net.Dialer Control hook for gRPC service
// discovery. It runs after resolution and before connect, with the address the
// socket is about to use, and enforces the same SSRF policy as the tech probe.
func refuseBlockedGrpcAddress(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("refusing to probe %q: cannot read its address: %w", address, err)
	}
	if reason, deny := discovery.BlockedProbeTarget(net.ParseIP(host)); deny {
		return fmt.Errorf("refusing to probe %s: %s address", host, reason)
	}
	return nil
}

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

	// SSRF prevention. A literal loopback/link-local/unspecified target is
	// rejected up front for a clear error, but the guarantee is the dialer's
	// Control hook below: it runs after the name is resolved and before the
	// socket connects, on every address gRPC actually dials, so a hostname that
	// resolves to a blocked range -- or rebinds between a URL check and the dial
	// -- cannot slip past. The weak check this replaces compared the raw host
	// string to three literals, so 127.0.0.2, 169.254.169.254 (cloud instance
	// metadata) and any name resolving to them went straight through.
	if h, _, err := net.SplitHostPort(host); err == nil {
		if reason, deny := discovery.BlockedProbeTarget(net.ParseIP(h)); deny {
			return nil, fmt.Errorf("refusing to probe %s: %s address", h, reason)
		}
	}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithContextDialer(func(dialCtx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second, Control: refuseBlockedGrpcAddress}).DialContext(dialCtx, "tcp", addr)
	}))
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

	conn, err := grpc.NewClient(host, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", host, err)
	}
	defer conn.Close()

	client := reflectionv1.NewServerReflectionClient(conn)
	stream, err := client.ServerReflectionInfo(dialCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create reflection stream: %w", err)
	}

	if err := stream.Send(&reflectionv1.ServerReflectionRequest{
		MessageRequest: &reflectionv1.ServerReflectionRequest_ListServices{
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
