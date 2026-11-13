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

	"github.com/gsoultan/gateon/internal/auth/authtest"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// callGRPC calls procedure through the management handler the way the
// transport carries it -- a gRPC frame over HTTP/2 with contentType -- adding
// the Sec-Fetch-Mode header every browser sends when browser is set, and
// decodes the reply into reply. It reports whether a reply message came back.
func callGRPC(t *testing.T, h http.Handler, procedure, contentType string, browser bool, in, reply proto.Message) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	msg, err := proto.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	frame := make([]byte, 5+len(msg))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(msg))) //nolint:gosec // a few bytes, not 4 GiB
	copy(frame[5:], msg)

	req := httptest.NewRequest(http.MethodPost, "http://gateway.example/gateon.v1.ApiService/"+procedure, bytes.NewReader(frame))
	req.ProtoMajor, req.ProtoMinor, req.Proto = 2, 0, "HTTP/2.0"
	req.Header.Set("Content-Type", contentType)
	if browser {
		req.Header.Set("Sec-Fetch-Mode", "cors")
	}
	req.RemoteAddr = "203.0.113.9:5555"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body := rr.Body.Bytes()
	if len(body) < 5 || body[0] != 0 {
		return rr, false
	}
	n := int(binary.BigEndian.Uint32(body[1:5]))
	if len(body) < 5+n || proto.Unmarshal(body[5:5+n], reply) != nil {
		return rr, false
	}
	return rr, true
}

// signInOverGRPC runs a whole sign-in as root over gRPC -- Login, Enroll2FA
// the first time, Verify2FA -- and returns the second step's reply. secret
// carries the enrolled authenticator from one call to the next.
func signInOverGRPC(t *testing.T, h http.Handler, contentType string, browser bool, secret *string) (*httptest.ResponseRecorder, *gateonv1.Verify2FAResponse) {
	t.Helper()
	var login gateonv1.LoginResponse
	if rr, ok := callGRPC(t, h, "Login", contentType, browser,
		&gateonv1.LoginRequest{Username: "root", Password: "correct-horse"}, &login); !ok {
		return rr, nil
	}
	if login.GetToken() != "" {
		t.Fatalf("the password alone answered a session over gRPC")
	}
	id := login.GetUser().GetId()
	if login.GetTwoFactorSetupRequired() {
		var enrol gateonv1.Enroll2FAResponse
		if rr, ok := callGRPC(t, h, "Enroll2FA", contentType, browser,
			&gateonv1.Enroll2FARequest{Username: "root", Password: "correct-horse"}, &enrol); !ok {
			t.Fatalf("Enroll2FA over gRPC: status %d, grpc-status %q", rr.Code, rr.Header().Get("Grpc-Status"))
		}
		id, *secret = enrol.GetId(), enrol.GetSecret()
	}
	code, err := authtest.Code(*secret)
	if err != nil {
		t.Fatal(err)
	}
	var verified gateonv1.Verify2FAResponse
	rr, ok := callGRPC(t, h, "Verify2FA", contentType, browser,
		&gateonv1.Verify2FARequest{Id: id, Code: code, Challenge: login.GetTwoFactorChallenge()}, &verified)
	if !ok {
		t.Fatalf("Verify2FA over gRPC: status %d, grpc-status %q", rr.Code, rr.Header().Get("Grpc-Status"))
	}
	return rr, &verified
}

// TestAGRPCClientCanFinishASignIn is the regression test for a sign-in that
// could not be completed over gRPC.
//
// Root cause: the second step existed only as REST endpoints, so the Login RPC
// answered an account with a second factor a challenge nothing on gRPC would
// take. Every account has one now (ADR 0087), which made that every sign-in.
func TestAGRPCClientCanFinishASignIn(t *testing.T) {
	h, mgr, _ := buildManagementHandler(t)
	var secret string
	for _, step := range []string{"first sign-in, enrolling", "second sign-in, with the code"} {
		_, reply := signInOverGRPC(t, h, "application/grpc", false, &secret)
		if !reply.GetSuccess() || reply.GetToken() == "" {
			t.Fatalf("%s: no session over gRPC: %v", step, reply)
		}
		if _, err := mgr.VerifyToken(reply.GetToken()); err != nil {
			t.Errorf("%s: the session does not verify: %v", step, err)
		}
	}
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
	var secret string

	_, native := signInOverGRPC(t, h, "application/grpc", false, &secret)
	if native.GetToken() == "" {
		t.Fatalf("a native gRPC client signing in got no token: %v", native)
	}
	if _, err := mgr.VerifyToken(native.GetToken()); err != nil {
		t.Errorf("the native client's token does not verify: %v", err)
	}

	rr, browser := signInOverGRPC(t, h, "application/grpc", true, &secret)
	if browser.GetUser().GetUsername() != "root" || !browser.GetSuccess() {
		t.Fatalf("the browser's sign-in did not succeed: status %d, reply %v", rr.Code, browser)
	}
	if browser.GetToken() != "" {
		t.Errorf("a browser signing in over gRPC was handed the session token in the reply")
	}

	// gRPC-Web does not reach Login: the management server hands it to grpc-go
	// unconverted, which refuses the content type before any RPC runs. Pinned
	// so that wiring gRPC-Web up later cannot hand a browser the token either.
	for _, ct := range []string{"application/grpc-web+proto", "application/grpc-web-text"} {
		var reply gateonv1.LoginResponse
		rr, _ := callGRPC(t, h, "Login", ct, true, &gateonv1.LoginRequest{Username: "root", Password: "correct-horse"}, &reply)
		if reply.GetToken() != "" || strings.Contains(rr.Body.String(), "v4.local.") {
			t.Errorf("a browser signing in over %s was handed a session token", ct)
		}
	}
}
