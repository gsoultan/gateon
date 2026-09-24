// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// stalledDispatcher is an alert endpoint that has stopped answering: a
// rate-limited webhook, a chat outage, a black-holed route. Every Send waits
// until released or until its own timeout.
type stalledDispatcher struct{ release chan struct{} }

func (s stalledDispatcher) Send(ctx context.Context, _ telemetry.SecurityThreat) error {
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TestAlertDeliveryIsBoundedWhenTheEndpointStalls covers alerting under the
// load it exists for.
//
// Threats arrive at whatever rate an attacker drives them -- every blocked
// request is one -- and each matching playbook started a delivery goroutine
// per threat per dispatcher, each holding an outbound connection for up to
// ten seconds. With the endpoint stalled nothing bounded them: goroutines,
// sockets and file descriptors grew with the attack's request rate, on the
// same process that has to keep accepting connections.
func TestAlertDeliveryIsBoundedWhenTheEndpointStalls(t *testing.T) {
	stalled := stalledDispatcher{release: make(chan struct{})}
	t.Cleanup(func() { close(stalled.release) })
	m := &AlertingManager{
		config: &gateonv1.AlertingConfig{
			Enabled: true,
			Playbooks: []*gateonv1.AlertPlaybook{{
				Id: "pb", EventType: "all", DispatcherIds: []string{"slow"},
			}},
		},
		dispatchers: map[string]Dispatcher{"slow": stalled},
	}

	before := runtime.NumGoroutine()
	const threats = 500
	for i := range threats {
		m.process(&telemetry.SecurityThreat{
			ID: fmt.Sprintf("t%d", i), Type: "waf_block", SourceIP: "203.0.113.9",
		})
	}
	if grown := runtime.NumGoroutine() - before; grown > threats/4 {
		t.Fatalf("%d threats against a stalled endpoint left %d delivery goroutines "+
			"running: alert delivery grows with the attack's request rate", threats, grown)
	}
}
