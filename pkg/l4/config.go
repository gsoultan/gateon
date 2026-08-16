// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

// L4Config holds L4 proxy configuration.
type L4Config struct {
	Backends            []string
	LoadBalancer        string
	HealthCheckInterval int  // ms, 0 = disabled
	HealthCheckTimeout  int  // ms
	EnableHealthCheck   bool // New field
	UDPSessionTimeout   int  // seconds
	ProxyProtocol       bool // send HAProxy PROXY protocol v1 header (TCP only)

	// UDPMaxSessions bounds the UDP session table. 0 selects
	// DefaultUDPMaxSessions. See udp.go for why an explicit ceiling is not
	// optional here: the table is keyed by client address, and a UDP source
	// address is whatever the sender wrote in the packet.
	UDPMaxSessions int
}
