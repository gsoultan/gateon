// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// loginOverGRPC calls the Login RPC through the management handler the way
// the transport carries it -- a gRPC frame over HTTP/2 with contentType --
// adding the Sec-Fetch-Mode header every browser sends when browser is set.
func loginOverGRPC(t *testing.T, h http.Handler, contentType string, browser bool) (*httptest.ResponseRecorder, *gateonv1.LoginResponse) {
	t.Helper()
	msg, err := proto.Marshal(&gateonv1.LoginRequest{Username: "root", Password: "correct-horse"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	frame := make([]byte, 5+len(msg))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(msg))) //nolint:gosec // a few bytes, not 4 GiB
	copy(frame[5:], msg)

	req := httptest.NewRequest(http.MethodPost, "http://gateway.example/gateon.v1.ApiService/Login", bytes.NewReader(frame))
	req.ProtoMajor, req.ProtoMinor, req.Proto = 2, 0, "HTTP/2.0"
	req.Header.Set("Content-Type", contentType)
	if browser {
		req.Header.Set("Sec-Fetch-Mode", "cors")
	}
	req.RemoteAddr = "203.0.113.9:5555"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr, loginReply(rr.Body.Bytes())
}

// loginReply decodes the one message of a gRPC reply body, or returns nil.
func loginReply(body []byte) *gateonv1.LoginResponse {
	if len(body) < 5 || body[0] != 0 {
		return nil
	}
	n := int(binary.BigEndian.Uint32(body[1:5]))
	if len(body) < 5+n {
		return nil
	}
	var resp gateonv1.LoginResponse
	if proto.Unmarshal(body[5:5+n], &resp) != nil {
		return nil
	}
	return &resp
}

// TestABrowserSigningInOverGRPCGetsNoToken: POST /v1/login answers a browser
// with the session cookie alone, because a token in the body is readable by
// any script in the page. The Login RPC answered everyone with the token in
// the reply, and a browser can make that call -- script on the dashboard's
// origin sending application/grpc over HTTP/2. The management server hands
// gRPC to grpc-go's ServeHTTP transport, which copies the request's headers
// into the call's metadata, Sec-Fetch-Mode included, so Login can tell.
//
// Root cause: the Sec-Fetch-Mode rule was applied in the REST handler only.
func TestABrowserSigningInOverGRPCGetsNoToken(t *testing.T) {
	h, mgr, _ := buildManagementHandler(t)

	_, native := loginOverGRPC(t, h, "application/grpc", false)
	if native.GetToken() == "" {
		t.Fatalf("a native gRPC client signing in got no token: %v", native)
	}
	if _, err := mgr.VerifyToken(native.GetToken()); err != nil {
		t.Errorf("the native client's token does not verify: %v", err)
	}

	rr, browser := loginOverGRPC(t, h, "application/grpc", true)
	if browser.GetUser().GetUsername() != "root" {
		t.Fatalf("the browser's sign-in did not succeed: status %d, reply %v", rr.Code, browser)
	}
	if browser.GetToken() != "" {
		t.Errorf("a browser signing in over gRPC was handed the session token in the reply")
	}

	// gRPC-Web does not reach Login: the management server hands it to grpc-go
	// unconverted, which refuses the content type before any RPC runs. Pinned
	// so that wiring gRPC-Web up later cannot hand a browser the token either.
	for _, ct := range []string{"application/grpc-web+proto", "application/grpc-web-text"} {
		rr, reply := loginOverGRPC(t, h, ct, true)
		if reply.GetToken() != "" || strings.Contains(rr.Body.String(), "v4.local.") {
			t.Errorf("a browser signing in over %s was handed a session token", ct)
		}
	}
}
