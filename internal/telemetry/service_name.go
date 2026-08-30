// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"strings"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// DefaultServiceName is what traces were always labelled with, kept as the
// fallback. It is not a good name, but changing it for installs that never set
// one would silently rename an existing service in their trace backend and
// orphan every dashboard and alert built on it.
const DefaultServiceName = "server"

// ResolveServiceName picks the name traces are reported under.
//
// otel.service_name was in the schema and rendered in the dashboard while
// InitTracer was called with a hardcoded "server", so every gateway in a trace
// backend reported as the same service and instances could not be told apart.
//
// getenv is injected to keep this a pure function. OTEL_SERVICE_NAME wins over
// the config file because it is the name the OpenTelemetry spec gives this
// setting, and an orchestrator setting it per-replica should not be overridden
// by a value baked into a shared config.
func ResolveServiceName(conf *gateonv1.OtelConfig, getenv func(string) string) string {
	if v := strings.TrimSpace(getenv("OTEL_SERVICE_NAME")); v != "" {
		return v
	}
	if conf != nil {
		if v := strings.TrimSpace(conf.GetServiceName()); v != "" {
			return v
		}
	}
	return DefaultServiceName
}
