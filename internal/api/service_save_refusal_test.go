// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestServiceSaveRefusalIsInvalidArgumentOverConnect: the gRPC transport
// refuses what REST refuses, as a client error naming the setting.
func TestServiceSaveRefusalIsInvalidArgumentOverConnect(t *testing.T) {
	svcs := &paritySvcStore{items: map[string]*gateonv1.Service{}}
	rts := newParityRouteStore()
	s := &ApiService{Services: svcs, Routes: rts, Invalidator: &parityInvalidator{routes: rts}}

	_, err := s.UpdateService(context.Background(), &gateonv1.UpdateServiceRequest{Service: &gateonv1.Service{
		Id: "hc", HealthCheckType: gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP,
		WeightedTargets: []*gateonv1.Target{{Url: "http://a:80", Weight: 1}},
	}})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "needs a path") {
		t.Fatalf("err = %v, want InvalidArgument saying an HTTP health check needs a path", err)
	}
	if _, ok := svcs.items["hc"]; ok {
		t.Fatal("the refused service was stored")
	}
}
