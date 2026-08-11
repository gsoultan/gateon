// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"fmt"
	"net"
)

func main() {
	ln, err := net.Listen("tcp", ":8084")
	if err != nil {
		panic(err)
	}
	fmt.Println("TCP backend listening on :8084")
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Printf("TCP Backend: New connection from %s\n", conn.RemoteAddr())
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		text := scanner.Text()
		fmt.Printf("TCP Backend Received: %s\n", text)
		fmt.Fprintf(conn, "TCP Echo: %s\n", text)
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("TCP Backend Error: %v\n", err)
	}
	fmt.Printf("TCP Backend: Connection closed from %s\n", conn.RemoteAddr())
}
