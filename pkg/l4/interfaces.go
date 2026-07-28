package l4

import (
	"context"
	"net"
)

// TCPProxy proxies a single TCP connection to a backend.
type TCPProxy interface {
	ProxyTCP(ctx context.Context, client net.Conn)
}

// UDPProxy handles UDP packets for an entrypoint.
type UDPProxy interface {
	HandlePacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte)
	Stop()
}
