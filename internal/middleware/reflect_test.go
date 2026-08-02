// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"crypto/tls"
	"testing"
)

func TestAccessExtensions(t *testing.T) {
	hello := &tls.ClientHelloInfo{}
	_ = hello.Extensions
}
