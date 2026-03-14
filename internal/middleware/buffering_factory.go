package middleware

import (
	"fmt"
	"strconv"
)

func (f *Factory) createBuffering(cfg map[string]string) (Middleware, error) {
	s := cfg["max_request_body_bytes"]
	if s == "" {
		return nil, fmt.Errorf("buffering requires max_request_body_bytes")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return nil, fmt.Errorf("buffering max_request_body_bytes must be a positive integer")
	}
	return MaxBodySize(n), nil
}
