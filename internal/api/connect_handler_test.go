// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestConnectServesTheRPCsTheDashboardCalls covers the five RPCs the dashboard
// calls over Connect that ConnectHandler never forwarded. It embeds the
// generated UnimplementedApiServiceHandler, so a method it does not define
// compiles and answers every call with "unimplemented": the first-run setup
// wizard could not create the administrator, and the trace visualizer, the CORS
// validator and the Cloudflare trust-list import all failed.
//
// Each call is made with input ApiService refuses before doing any work, and the
// context is cancelled so nothing can reach the network. What is asserted is the
// ApiService's own answer, which only arrives if the call was forwarded.
func TestConnectServesTheRPCsTheDashboardCalls(t *testing.T) {
	h := NewConnectHandler(&ApiService{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := []struct {
		rpc  string
		want string
		call func() (string, error)
	}{
		{"Setup", "paseto secret must be exactly 32 characters", func() (string, error) {
			res, err := h.Setup(ctx, connect.NewRequest(&gateonv1.SetupRequest{PasetoSecret: "short"}))
			if err != nil {
				return "", err
			}
			return res.Msg.GetError(), nil
		}},
		{"ValidateCORS", "URL is required", func() (string, error) {
			res, err := h.ValidateCORS(ctx, connect.NewRequest(&gateonv1.ValidateCORSRequest{}))
			if err != nil {
				return "", err
			}
			return res.Msg.GetMessage(), nil
		}},
		{"TraceRoute", "IP address is required", func() (string, error) {
			_, err := h.TraceRoute(ctx, connect.NewRequest(&gateonv1.TraceRouteRequest{}))
			return "", err
		}},
		{"GetCloudflareIPs", "context canceled", func() (string, error) {
			_, err := h.GetCloudflareIPs(ctx, connect.NewRequest(&gateonv1.GetCloudflareIPsRequest{}))
			return "", err
		}},
		{"RunDeepScan", "ClamAV manager not initialized", func() (string, error) {
			res, err := h.RunDeepScan(ctx, connect.NewRequest(&gateonv1.RunDeepScanRequest{}))
			if err != nil {
				return "", err
			}
			return res.Msg.GetMessage(), nil
		}},
	}

	for _, c := range calls {
		t.Run(c.rpc, func(t *testing.T) {
			msg, err := c.call()
			if connect.CodeOf(err) == connect.CodeUnimplemented {
				t.Fatalf("%s is not implemented over Connect: %v", c.rpc, err)
			}
			got := msg
			if err != nil {
				got = err.Error()
			}
			if !strings.Contains(got, c.want) {
				t.Errorf("%s answered %q, want ApiService's %q", c.rpc, got, c.want)
			}
		})
	}
}
