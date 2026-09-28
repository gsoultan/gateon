// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// recordingGRPCWeb stands in for the internal gRPC server: it says yes to
// gRPC-Web and records whether anything reached it.
type recordingGRPCWeb struct{ reached bool }

func (m *recordingGRPCWeb) IsGrpcWebRequest(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc-web")
}
func (m *recordingGRPCWeb) IsAcceptableGrpcCorsRequest(*http.Request) bool { return false }
func (m *recordingGRPCWeb) IsGrpcWebSocketRequest(*http.Request) bool      { return false }
func (m *recordingGRPCWeb) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	m.reached = true
	w.WriteHeader(http.StatusOK)
}

// TestGRPCOnATCPEntrypointGoesThroughTheBaseHandler: a plaintext TCP entrypoint
// handed every gRPC and gRPC-Web request straight to the internal gRPC server,
// ahead of the base handler -- which is where a data-plane entrypoint refuses
// the management API, and where the management API authenticates. The gRPC
// permission check then saw no caller and read that as "auth disabled", so
// anyone who could reach the port could call UpdateGlobalConfig with no
// credential at all. gRPC must reach the base handler like any other request.
func TestGRPCOnATCPEntrypointGoesThroughTheBaseHandler(t *testing.T) {
	for _, tc := range []struct {
		name        string
		protoMajor  int
		contentType string
	}{
		{"gRPC over cleartext HTTP/2", 2, "application/grpc"},
		{"gRPC-Web", 1, "application/grpc-web+proto"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := mockDepsForInspection(t)
			base := false
			deps.BaseHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				base = true
				w.WriteHeader(http.StatusUnauthorized)
			})
			internal := &recordingGRPCWeb{}
			deps.Wrapped = internal
			ep := &gateonv1.EntryPoint{Id: "tcp", Name: "tcp", Address: ":9000", Type: gateonv1.EntryPoint_TCP}

			req := httptest.NewRequest(http.MethodPost, "http://gateway.example.com/gateon.v1.ApiService/UpdateGlobalConfig", nil)
			req.ProtoMajor = tc.protoMajor
			req.Header.Set("Content-Type", tc.contentType)
			req.RemoteAddr = "198.51.100.44:40000"
			buildPlainHTTPHandler(ep, deps).ServeHTTP(httptest.NewRecorder(), req)

			if internal.reached || !base {
				t.Fatalf("%s to the management API on a TCP entrypoint: internal gRPC server reached=%v, "+
					"base handler reached=%v; want the base handler, which authenticates, and never the server directly",
					tc.name, internal.reached, base)
			}
		})
	}
}
