// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// tarpitThresholdWords is what the gateway says about a tarpit without a
// threshold. Spelled out rather than imported, so the test cannot pass by
// agreeing with a changed constant.
const tarpitThresholdWords = "set a threat score threshold above 0"

// TestTarpitWithoutAThresholdIsRefusedOnEveryTransport: the dashboard refused
// a tarpit with no threshold above 0 or no maximum delay (ADR 0063), and the
// gateway saved one from REST, gRPC and an import, which the factory then built
// comparing every client's threat score with 0. Each transport is refused with
// the dashboard's words, and nothing is written.
func TestTarpitWithoutAThresholdIsRefusedOnEveryTransport(t *testing.T) {
	unset := func() *gateonv1.Middleware {
		return &gateonv1.Middleware{Id: "slow", Name: "slow", Type: "tarpit",
			Config: map[string]string{"base_delay": "500ms", "max_delay": "5s"}}
	}

	t.Run("REST", func(t *testing.T) {
		a, _ := newMwAPI(t, auth.RoleOperator)
		live, file := a.snapshot(t)
		code, body := a.put(t, unset())
		requireRefused(t, "a tarpit without a threshold", code, body, `config \"threshold\"`, tarpitThresholdWords)
		if strings.Contains(body, "goroutine") || strings.Contains(body, ".go:") {
			t.Errorf("the refusal carries internals: %s", body)
		}
		a.requireUnchanged(t, "a refused tarpit", live, file)

		noMax := unset()
		noMax.Config = map[string]string{"threshold": "50"}
		code, body = a.put(t, noMax)
		requireRefused(t, "a tarpit without a maximum delay", code, body, `config \"max_delay\"`, "set a maximum delay")
		a.requireUnchanged(t, "a refused tarpit", live, file)

		ok := unset()
		ok.Config["threshold"] = "50"
		if code, body := a.put(t, ok); code != http.StatusOK {
			t.Fatalf("a tarpit with a threshold and a maximum delay was answered %d %s; it must save", code, body)
		}
	})

	t.Run("gRPC", func(t *testing.T) {
		a, _ := newMwAPI(t, auth.RoleOperator)
		live, file := a.snapshot(t)
		_, err := a.grpc.UpdateMiddleware(context.Background(), &gateonv1.UpdateMiddlewareRequest{Middleware: unset()})
		if err == nil || !strings.Contains(err.Error(), tarpitThresholdWords) {
			t.Fatalf("gRPC UpdateMiddleware of a tarpit without a threshold: %v; it must be refused with the reason", err)
		}
		a.requireUnchanged(t, "a tarpit refused over gRPC", live, file)
	})

	t.Run("import", func(t *testing.T) {
		a, _ := newMwAPI(t, auth.RoleAdmin)
		live, file := a.snapshot(t)
		body := marshalImport(t, map[string]any{"middlewares": []*gateonv1.Middleware{unset()}})
		_, out := a.do(t, http.MethodPost, "/v1/config/import", body)
		if !strings.Contains(string(out), "slow") || !strings.Contains(string(out), tarpitThresholdWords) {
			t.Errorf("the import did not refuse the tarpit with its reason: %s", out)
		}
		a.requireUnchanged(t, "an imported tarpit without a threshold", live, file)
	})
}
