// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package config

// RouteFilter filters routes by type, host, path, and status.
type RouteFilter struct {
	Type   string // http, grpc, graphql, tcp, udp
	Host   string
	Path   string
	Status string // active, paused
}
