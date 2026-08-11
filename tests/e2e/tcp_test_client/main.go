// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	time.Sleep(2 * time.Second) // Wait for routing to be ready
	fmt.Println("Dialing TCP at localhost:8086...")
	conn, err := net.DialTimeout("tcp", "localhost:8086", time.Second*10)
	if err != nil {
		fmt.Printf("Dial Error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Println("TCP connected, sending message...")

	fmt.Fprintf(conn, "Gateon TCP Test: This is exactly 24 bytes plus newline\n")
	fmt.Println("Message sent, waiting for response...")
	message, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("Read Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Response: %s", message)
}
