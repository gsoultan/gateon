// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wait-for-port <host:port>")
		os.Exit(1)
	}
	addr := os.Args[1]
	timeout := 30 * time.Second
	start := time.Now()
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			fmt.Printf("Port %s is up!\n", addr)
			return
		}
		if time.Since(start) > timeout {
			fmt.Printf("Timeout waiting for port %s\n", addr)
			os.Exit(1)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
