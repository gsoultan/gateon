package middleware

import (
	"crypto/tls"
	"testing"
)

func TestAccessExtensions(t *testing.T) {
	hello := &tls.ClientHelloInfo{}
	_ = hello.Extensions
}
