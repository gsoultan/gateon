// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/telemetry/tracearchive"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
)

// The handler Run mounts carries ApiService's gRPC statuses to Connect
// clients as their own codes and messages. Mounted bare, connect-go sent every
// one of them as Unknown over HTTP 500 with "rpc error: code = ..." as the
// text, so the dashboard could not tell a refused request from a failure.
func TestAPIConnectHandler_CarriesStatusCodes(t *testing.T) {
	t.Setenv(tracearchive.EnvDir, t.TempDir())
	mux := http.NewServeMux()
	mux.Handle(apiConnectHandler(&api.ApiService{}))
	// The base handler's decision for a deployment with authentication off;
	// this test is about status codes, not about who may call.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(middleware.WithAuthNotRequired(r.Context())))
	}))
	defer srv.Close()
	client := gateonv1connect.NewApiServiceClient(srv.Client(), srv.URL)
	ctx := context.Background()

	for name, tc := range map[string]struct {
		call func() error
		code connect.Code
		msg  string
	}{
		"a refused request": {func() error {
			_, err := client.TraceRoute(ctx, connect.NewRequest(&gateonv1.TraceRouteRequest{}))
			return err
		}, connect.CodeInvalidArgument, "IP address is required"},
		"something that is not there": {func() error {
			_, err := client.GetTrace(ctx, connect.NewRequest(&gateonv1.GetTraceRequest{
				Id: "gone", Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			}))
			return err
		}, connect.CodeNotFound, "trace not found"},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.call()
			var ce *connect.Error
			if !errors.As(err, &ce) || ce.Code() != tc.code || ce.Message() != tc.msg {
				t.Fatalf("got %v, want %v %q", err, tc.code, tc.msg)
			}
		})
	}
}
