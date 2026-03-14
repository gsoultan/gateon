package proxy

import "time"

// TransportConfig tunes HTTP transport connection pooling for high-throughput backends.
// Use explicit values; zero values use production defaults.
type TransportConfig struct {
	MaxIdleConns          int           // 0 = DefaultMaxIdleConns
	MaxIdleConnsPerHost   int           // 0 = DefaultMaxIdleConnsPerHost
	IdleConnTimeout       time.Duration // 0 = DefaultIdleConnTimeout
}

const (
	DefaultMaxIdleConns        = 10000
	DefaultMaxIdleConnsPerHost = 1000
	DefaultIdleConnTimeout     = 90 * time.Second
)

func (c *TransportConfig) maxIdleConns() int {
	if c != nil && c.MaxIdleConns > 0 {
		return c.MaxIdleConns
	}
	return DefaultMaxIdleConns
}

func (c *TransportConfig) maxIdleConnsPerHost() int {
	if c != nil && c.MaxIdleConnsPerHost > 0 {
		return c.MaxIdleConnsPerHost
	}
	return DefaultMaxIdleConnsPerHost
}

func (c *TransportConfig) idleConnTimeout() time.Duration {
	if c != nil && c.IdleConnTimeout > 0 {
		return c.IdleConnTimeout
	}
	return DefaultIdleConnTimeout
}
