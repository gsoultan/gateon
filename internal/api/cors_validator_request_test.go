// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestValidateCORSInvalidMethodIsRejected: the method is caller-supplied and
// http.NewRequest rejects anything that is not an HTTP token, returning a nil
// request. The validator discarded that error and dereferenced the nil request,
// which wedged the calling goroutine instead of answering.
//
// Unfixed, this test does not fail -- it never returns, and the package times
// out after ten minutes.
func TestValidateCORSInvalidMethodIsRejected(t *testing.T) {
	mw := &gateonv1.Middleware{
		Id: "cors-1", Name: "cors", Type: "cors",
		Config: map[string]string{"allowed_origins": "https://example.com"},
	}
	rt := &gateonv1.Route{
		Id: "rt1", Name: "api", Rule: "Path(`/api/test`)", Middlewares: []string{"cors-1"},
	}
	svc := &ApiService{
		Routes:      &mockRouteStore{routes: []*gateonv1.Route{rt}},
		Middlewares: &mockMiddlewareStore{middlewares: map[string]*gateonv1.Middleware{"cors-1": mw}},
	}

	resp, err := svc.ValidateCORS(context.Background(), &gateonv1.ValidateCORSRequest{
		Url: "http://gateon/api/test", Origin: "https://example.com", Method: "GET X",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsAllowed {
		t.Fatalf("an unparseable method must not validate as allowed: %+v", resp)
	}
}
