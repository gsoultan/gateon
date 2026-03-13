package l4

// L4Config holds L4 proxy configuration.
type L4Config struct {
	Backends            []string
	LoadBalancer        string
	HealthCheckInterval int // ms, 0 = disabled
	HealthCheckTimeout  int // ms
	UDPSessionTimeout   int // seconds
}
