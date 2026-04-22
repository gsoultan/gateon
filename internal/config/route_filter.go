package config

// RouteFilter filters routes by type, host, path, and status.
type RouteFilter struct {
	Type   string // http, grpc, graphql, tcp, udp
	Host   string
	Path   string
	Status string // active, paused
}
