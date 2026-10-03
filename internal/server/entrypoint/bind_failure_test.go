// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/server/readiness"
	"github.com/gsoultan/gateon/internal/syncutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// holdPort listens on a loopback port for the life of the test, so a listener
// the test starts on the same address cannot bind.
func holdPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.Addr().String()
}

// namesEntrypoint reports whether readiness has a reason naming id.
func namesEntrypoint(id string) bool {
	return slices.ContainsFunc(readiness.NotReady(), func(r string) bool { return strings.Contains(r, id) })
}

// TestAnEntrypointThatCannotBindIsNotReady: an entrypoint whose port another
// process held logged an error, and /readyz and /healthz both said 200, so a
// load balancer and the service manager kept treating a gateway that served
// nothing on its main port as healthy. HTTP and TCP entrypoints alike.
func TestAnEntrypointThatCannotBindIsNotReady(t *testing.T) {
	for _, tc := range []struct {
		id  string
		typ gateonv1.EntryPoint_Type
	}{
		{"bindfail-http", gateonv1.EntryPoint_HTTP},
		{"bindfail-tcp", gateonv1.EntryPoint_TCP},
	} {
		t.Run(tc.id, func(t *testing.T) {
			deps := mockDepsForInspection(t)
			ep := &gateonv1.EntryPoint{Id: tc.id, Name: tc.id, Address: holdPort(t), Type: tc.typ}
			wg := &syncutil.WaitGroup{}
			runnerFor(ep.Type).Run(t.Context(), ep, deps, wg)
			t.Cleanup(func() { deps.ShutdownRegistry.ShutdownAll(t.Context()); wg.Wait() })

			if !namesEntrypoint(tc.id) {
				t.Errorf("entrypoint %s could not bind %s and readiness does not say so: %q",
					tc.id, ep.Address, readiness.NotReady())
			}
		})
	}
}

// TestAnEntrypointThatBindsIsNotReported is the control.
func TestAnEntrypointThatBindsIsNotReported(t *testing.T) {
	deps := mockDepsForInspection(t)
	ep := &gateonv1.EntryPoint{Id: "bindok-tcp", Name: "bindok-tcp", Address: "127.0.0.1:0", Type: gateonv1.EntryPoint_TCP}
	wg := &syncutil.WaitGroup{}
	runnerFor(ep.Type).Run(t.Context(), ep, deps, wg)
	t.Cleanup(func() { deps.ShutdownRegistry.ShutdownAll(t.Context()); wg.Wait() })
	if namesEntrypoint("bindok-tcp") {
		t.Errorf("an entrypoint that bound is reported not ready: %q", readiness.NotReady())
	}
}

// TestTheManagementListenerFailingToBindIsAnError: with the management port
// taken the gateway logged "Management listen failed" and ran on with no
// management plane -- nothing to configure it, sign in to or probe -- while
// the service manager saw a healthy process. Starting it must fail, so Run
// exits non-zero and systemd restarts it.
func TestTheManagementListenerFailingToBindIsAnError(t *testing.T) {
	for _, env := range []string{"GATEON_MANAGEMENT_BIND", "GATEON_MANAGEMENT_PORT",
		"GATEON_MANAGEMENT_ALLOWED_IPS", "GATEON_MANAGEMENT_HOST"} {
		t.Setenv(env, "")
	}
	held := holdPort(t)
	_, port, _ := net.SplitHostPort(held)
	deps := mockDepsForInspection(t)
	deps.ManagementConfig = &gateonv1.ManagementConfig{Bind: "127.0.0.1", Port: port}
	wg := &syncutil.WaitGroup{}
	err := startSecureManagementServer("0", deps, wg)
	t.Cleanup(func() { deps.ShutdownRegistry.ShutdownAll(t.Context()); wg.Wait() })
	if err == nil {
		t.Fatalf("the management listener could not bind %s and starting it did not fail", held)
	}
	if !strings.Contains(err.Error(), held) {
		t.Errorf("the error does not name the address: %v", err)
	}
}
