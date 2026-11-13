// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type builtinCAAPI struct {
	GlobalAndAuthAPI
	svc *api.ApiService
}

func (b builtinCAAPI) ListBuiltinCertificateAuthorities(ctx context.Context, req *gateonv1.ListBuiltinCertificateAuthoritiesRequest) (*gateonv1.ListBuiltinCertificateAuthoritiesResponse, error) {
	return b.svc.ListBuiltinCertificateAuthorities(ctx, req)
}

func getBuiltinCAs(t *testing.T, claims *auth.Claims, query string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerCertHandlers(mux, builtinCAAPI{svc: &api.ApiService{}})
	req := httptest.NewRequest(http.MethodGet, "/v1/certs/builtin"+query, nil)
	if claims != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, claims))
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// REST answers what the RPC answers, page for page, so the dashboard and a
// gRPC client choose from the same list.
func TestBuiltinCAsOverRESTMatchTheRPC(t *testing.T) {
	viewer := &auth.Claims{ID: "v-1", Username: "viewer", Role: auth.RoleViewer}
	for _, q := range []struct {
		query          string
		page, pageSize int32
	}{{"", 0, 0}, {"?page=1&pageSize=1", 1, 1}} {
		rr := getBuiltinCAs(t, viewer, q.query)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %q: status %d body %q", q.query, rr.Code, rr.Body.String())
		}
		var got gateonv1.ListBuiltinCertificateAuthoritiesResponse
		if err := protojson.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		want, err := (&api.ApiService{}).ListBuiltinCertificateAuthorities(context.Background(),
			&gateonv1.ListBuiltinCertificateAuthoritiesRequest{Page: q.page, PageSize: q.pageSize})
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(&got, want) {
			t.Fatalf("GET %q:\nREST %v\nRPC  %v", q.query, &got, want)
		}
		if len(got.Authorities) == 0 || got.TotalCount != 3 {
			t.Fatalf("GET %q: %d entries of %d, want a non-empty page of 3", q.query, len(got.Authorities), got.TotalCount)
		}
	}
}

func TestBuiltinCAsRequireAuthentication(t *testing.T) {
	if rr := getBuiltinCAs(t, nil, ""); rr.Code == http.StatusOK {
		t.Fatalf("anonymous GET answered 200")
	}
}
