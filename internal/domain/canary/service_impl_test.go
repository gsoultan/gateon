// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package canary

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// fullService returns a Service with every field set to a distinctive non-zero
// value, so a copy that drops one is visible rather than plausible.
func fullService() *gateonv1.Service {
	return &gateonv1.Service{
		Id:                      "svc-1",
		Name:                    "checkout",
		LoadBalancerPolicy:      "weighted_round_robin",
		HealthCheckPath:         "/healthz",
		BackendType:             "tcp",
		L4HealthCheckIntervalMs: 2500,
		L4HealthCheckTimeoutMs:  750,
		L4UdpSessionTimeoutS:    90,
		L4ProxyProtocol:         true,
		DiscoveryUrl:            "dns:checkout.svc.local",
		TlsClientConfig:         &gateonv1.TlsClientConfig{Enabled: true, SkipVerify: true, ServerName: "checkout.internal"},
		HealthCheckPort:         8443,
		HealthCheckProtocol:     "https",
		HealthCheckType:         gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP,
		WeightedTargets: []*gateonv1.Target{{
			Url:                  "http://10.0.0.1:8080",
			Weight:               70,
			Protocol:             "h2c",
			ProxyProtocolEnabled: true,
		}},
	}
}

// TestSnapshotPreservesEveryField is the bug. The rollback copy was a
// hand-written struct literal naming ten of Service's fifteen fields and two of
// Target's five, so a canary that breached its error-rate or latency threshold
// rolled back to a service with its L4 timeouts zeroed and PROXY protocol
// switched off -- losing the backend's view of the real client address at
// exactly the moment someone was reading logs to find out what broke.
func TestSnapshotPreservesEveryField(t *testing.T) {
	t.Parallel()

	original := fullService()
	got := snapshotService(original)

	if !proto.Equal(original, got) {
		t.Errorf("snapshot lost data.\n original: %v\n      got: %v", original, got)
	}
}

// TestSnapshotCoversEveryDeclaredField walks the descriptor rather than a list
// someone maintains, so adding a field to the proto cannot quietly escape the
// snapshot the way fields 7 to 10 did.
func TestSnapshotCoversEveryDeclaredField(t *testing.T) {
	t.Parallel()

	original := fullService()
	got := snapshotService(original)

	fields := original.ProtoReflect().Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if !original.ProtoReflect().Has(fd) {
			t.Errorf("fullService leaves %s unset, so this test cannot prove the "+
				"snapshot preserves it; set it", fd.Name())
			continue
		}
		if !got.ProtoReflect().Has(fd) {
			t.Errorf("snapshot dropped field %s", fd.Name())
		}
	}
}

func TestSnapshotIsDeep(t *testing.T) {
	t.Parallel()

	original := fullService()
	got := snapshotService(original)

	// Mutating the snapshot must not reach the original, or a rollback would
	// restore whatever the canary had already done to it.
	got.WeightedTargets[0].Weight = 5
	got.TlsClientConfig.SkipVerify = false

	if original.WeightedTargets[0].Weight != 70 {
		t.Error("snapshot shares target memory with the original; a rollback " +
			"would restore the canary's own weights")
	}
	if !original.TlsClientConfig.SkipVerify {
		t.Error("snapshot shares the TLS client config with the original")
	}
}

func TestSnapshotOfNil(t *testing.T) {
	t.Parallel()

	if got := snapshotService(nil); got != nil {
		t.Errorf("snapshotService(nil) = %v, want nil", got)
	}
}

func TestSnapshotOfEmptyServiceHasNoTargets(t *testing.T) {
	t.Parallel()

	got := snapshotService(&gateonv1.Service{Id: "bare"})
	if got == nil {
		t.Fatal("snapshotService returned nil for a valid service")
	}
	if got.Id != "bare" {
		t.Errorf("Id = %q, want %q", got.Id, "bare")
	}
	if len(got.WeightedTargets) != 0 {
		t.Errorf("WeightedTargets = %v, want empty", got.WeightedTargets)
	}
}

// TestTargetFieldsAreAllCovered does for Target what the service-level test
// does for Service: Target grew proxy_protocol_enabled and
// proxy_protocol_version after the copy was written, and both were dropped.
func TestTargetFieldsAreAllCovered(t *testing.T) {
	t.Parallel()

	original := fullService()
	got := snapshotService(original)

	if len(got.WeightedTargets) != 1 {
		t.Fatalf("got %d targets, want 1", len(got.WeightedTargets))
	}

	src := original.WeightedTargets[0].ProtoReflect()
	dst := got.WeightedTargets[0].ProtoReflect()
	src.Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		if !dst.Has(fd) {
			t.Errorf("snapshot dropped target field %s", fd.Name())
		}
		return true
	})
}
