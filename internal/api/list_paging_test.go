// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestListCallsPageAndCountAsRESTDoes: the Connect and gRPC list calls
// ignored page, page_size and search, answered with everything, and reported
// a total_count of zero. The REST handlers paged and counted, so the same
// question asked over two transports had two answers.
func TestListCallsPageAndCountAsRESTDoes(t *testing.T) {
	dir := t.TempDir()
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	for _, id := range []string{"api-a", "api-b", "web"} {
		if err := routes.Update(t.Context(), &gateonv1.Route{Id: id, Rule: "PathPrefix(`/" + id + "`)", ServiceId: "s"}); err != nil {
			t.Fatal(err)
		}
		if err := services.Update(t.Context(), &gateonv1.Service{Id: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	s := &ApiService{Routes: routes, Services: services}

	rr, err := s.ListRoutes(t.Context(), &gateonv1.ListRoutesRequest{Page: 0, PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(rr.GetRoutes()) != 2 || rr.GetTotalCount() != 3 || rr.GetPageSize() != 2 {
		t.Errorf("routes page 0 of 2: got %d routes, total %d, page size %d; want 2, 3, 2",
			len(rr.GetRoutes()), rr.GetTotalCount(), rr.GetPageSize())
	}
	rr, err = s.ListRoutes(t.Context(), &gateonv1.ListRoutesRequest{Search: "api-"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rr.GetRoutes()) != 2 || rr.GetTotalCount() != 2 {
		t.Errorf("routes searched for api-: got %d, total %d; want 2, 2", len(rr.GetRoutes()), rr.GetTotalCount())
	}

	sr, err := s.ListServices(t.Context(), &gateonv1.ListServicesRequest{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(sr.GetServices()) != 1 || sr.GetTotalCount() != 3 {
		t.Errorf("services page 1 of 2: got %d, total %d; want 1, 3", len(sr.GetServices()), sr.GetTotalCount())
	}

	// A page size past the bound is clamped, not honoured.
	rr, err = s.ListRoutes(t.Context(), &gateonv1.ListRoutesRequest{PageSize: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if rr.GetPageSize() != MaxListPageSize {
		t.Errorf("page size 2^30 answered as %d, want the bound %d", rr.GetPageSize(), MaxListPageSize)
	}
}
