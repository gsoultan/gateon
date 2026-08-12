// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gsoultan/gateon/tests/e2e/testpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	fmt.Println("Dialing gRPC at localhost:8085...")
	conn, err := grpc.NewClient("localhost:8085", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Dial Error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Println("gRPC connected, creating client...")
	client := testpb.NewTestServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	fmt.Println("Calling Echo...")
	resp, err := client.Echo(ctx, &testpb.EchoRequest{Message: "Gateon Test"})
	if err != nil {
		fmt.Printf("Echo Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Response: %s\n", resp.GetMessage())
}
